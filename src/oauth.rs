use crate::{
    adapters::postgres::oauth::PgGrantStore,
    application::oauth::{self as application, Authorization, OAuth},
    auth,
    domain::oauth::{ClientCredentials, Error, Result, SecretVerifier, Subject, SUPPORTED_SCOPES},
    AppState,
};
use async_trait::async_trait;
use axum::{
    extract::{
        rejection::{FormRejection, QueryRejection},
        Form, OriginalUri, Query, State,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use url::Url;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/oauth/authorize", get(authorize))
        .route(
            "/api/v1/auth/oauth/consent/{id}",
            get(consent_get).post(consent_decide),
        )
        .route("/oauth/consent/complete/{id}", get(consent_complete))
        .route("/oauth/token", post(token))
        .route("/oauth/userinfo", get(userinfo))
        .with_state(state.clone())
        .merge(crate::oauth_grants::router(state))
}

struct HttpError(Error);
impl From<Error> for HttpError {
    fn from(error: Error) -> Self {
        Self(error)
    }
}
impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let (status, challenge) = match self.0 {
            Error::InvalidClient => (
                StatusCode::UNAUTHORIZED,
                Some("Basic realm=\"oauth/token\""),
            ),
            Error::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                Some("Bearer error=\"invalid_token\""),
            ),
            Error::InsufficientScope => (
                StatusCode::FORBIDDEN,
                Some("Bearer error=\"insufficient_scope\", scope=\"openid\""),
            ),
            Error::Dependency => (StatusCode::SERVICE_UNAVAILABLE, None),
            _ => (StatusCode::BAD_REQUEST, None),
        };
        let code = self.0.code();
        let mut response = (status, Json(json!({"error":code,"code":code}))).into_response();
        no_store(&mut response);
        if let Some(challenge) = challenge {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(challenge),
            );
        }
        response
    }
}
fn no_store(response: &mut Response) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}
fn redirect(mut uri: Url, state: Option<&str>, field: &str, value: &str) -> Response {
    uri.query_pairs_mut().append_pair(field, value);
    if let Some(state) = state {
        uri.query_pairs_mut().append_pair("state", state);
    }
    let mut response = Redirect::to(uri.as_str()).into_response();
    no_store(&mut response);
    response
}
async fn discovery(State(state): State<AppState>) -> Json<Value> {
    let issuer = state.config.issuer.trim_end_matches('/');
    Json(json!({
        "issuer":state.config.issuer,"authorization_endpoint":format!("{issuer}/oauth/authorize"),"token_endpoint":format!("{issuer}/oauth/token"),
        "userinfo_endpoint":format!("{issuer}/oauth/userinfo"),"jwks_uri":format!("{issuer}/.well-known/jwks.json"),
        "response_types_supported":["code"],"response_modes_supported":["query"],"grant_types_supported":["authorization_code","refresh_token"],
        "subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],
        "token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post"],"code_challenge_methods_supported":["S256"],
        "scopes_supported":SUPPORTED_SCOPES,"claims_supported":["iss","aud","sub","sid","exp","iat","nonce","email","email_verified"],
        "request_parameter_supported":false,"request_uri_parameter_supported":false
    }))
}
async fn jwks(State(state): State<AppState>) -> Json<Value> {
    Json(state.crypto.jwks())
}

#[derive(Deserialize, serde::Serialize)]
struct AuthorizeRequest {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    scope: String,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    response_mode: Option<String>,
    prompt: Option<String>,
}
async fn authorize(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    request: std::result::Result<Query<AuthorizeRequest>, QueryRejection>,
) -> std::result::Result<Response, HttpError> {
    let Query(request) = request.map_err(|_| Error::InvalidRequest)?;
    let store = PgGrantStore::new(state.db.clone(), state.crypto.clone());
    let service = OAuth::new(&store, &state.crypto, &state.config.issuer);
    let approved = match service
        .authorization(
            &request.client_id,
            Authorization {
                redirect_uri: &request.redirect_uri,
                response_type: &request.response_type,
                response_mode: request.response_mode.as_deref(),
                prompt: request.prompt.as_deref(),
                scope: &request.scope,
                nonce: request.nonce.as_deref(),
                challenge: request.code_challenge.as_deref(),
                challenge_method: request.code_challenge_method.as_deref(),
            },
        )
        .await
    {
        Ok(approved) => approved,
        Err(failure) => {
            return match failure.redirect {
                Some(uri) => Ok(redirect(
                    uri,
                    request.state.as_deref(),
                    "error",
                    failure.error.code(),
                )),
                None => Err(failure.error.into()),
            }
        }
    };
    let actor = match auth::authenticate(&state, &headers).await {
        Ok(actor) => actor,
        Err(error) if error.status == StatusCode::UNAUTHORIZED => {
            if request.prompt.as_deref() == Some("none") {
                return Ok(redirect(
                    approved.redirect,
                    request.state.as_deref(),
                    "error",
                    Error::LoginRequired.code(),
                ));
            }
            let path = uri
                .path_and_query()
                .map(|path| path.as_str())
                .unwrap_or("/oauth/authorize");
            let query = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("return_to", path)
                .finish();
            let mut response = Redirect::to(&format!("/?{query}")).into_response();
            no_store(&mut response);
            return Ok(response);
        }
        Err(_) => return Err(Error::Dependency.into()),
    };
    let policy: Option<bool> = sqlx::query_scalar(
        "SELECT trusted_first_party FROM oauth_clients WHERE client_id=$1 AND revoked_at IS NULL",
    )
    .bind(&request.client_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| Error::Dependency)?;
    let trusted = policy.ok_or(Error::InvalidClient)?;
    let scopes: Vec<String> = request
        .scope
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let consent:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oauth_consents WHERE user_id=$1 AND client_id=$2 AND scopes @> $3)").bind(actor.user_id).bind(&request.client_id).bind(&scopes).fetch_one(&state.db).await.map_err(|_|Error::Dependency)?;
    if !trusted && !consent {
        if request.prompt.as_deref() == Some("none") {
            return Ok(redirect(
                approved.redirect,
                request.state.as_deref(),
                "error",
                "consent_required",
            ));
        }
        let id = uuid::Uuid::now_v7();
        sqlx::query("INSERT INTO oauth_consent_requests(id,user_id,session_id,client_id,request,scopes) VALUES($1,$2,$3,$4,$5,$6)").bind(id).bind(actor.user_id).bind(actor.session_id).bind(&request.client_id).bind(serde_json::to_value(&request).map_err(|_|Error::Dependency)?).bind(scopes).execute(&state.db).await.map_err(|_|Error::Dependency)?;
        return Ok(Redirect::to(&format!("/oauth/consent?request_id={id}")).into_response());
    }
    let result = service
        .authorize(
            Subject {
                user_id: actor.user_id,
                session_id: actor.session_id,
            },
            &approved,
        )
        .await;
    match result {
        Ok(code) => Ok(redirect(
            approved.redirect,
            request.state.as_deref(),
            "code",
            &code,
        )),
        Err(Error::LoginRequired) => Ok(redirect(
            approved.redirect,
            request.state.as_deref(),
            "error",
            Error::LoginRequired.code(),
        )),
        Err(error) => Err(error.into()),
    }
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    client_id: Option<String>,
    client_secret: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    scope: Option<String>,
}
fn decode_basic_component(value: &str) -> Result<String> {
    if value.bytes().enumerate().any(|(index, byte)| {
        byte == b'%'
            && (index + 2 >= value.len()
                || !value.as_bytes()[index + 1].is_ascii_hexdigit()
                || !value.as_bytes()[index + 2].is_ascii_hexdigit())
    }) {
        return Err(Error::InvalidClient);
    }
    let encoded = format!("v={value}");
    let parsed = url::form_urlencoded::parse(encoded.as_bytes()).collect::<Vec<_>>();
    if parsed.len() != 1 {
        return Err(Error::InvalidClient);
    }
    Ok(parsed[0].1.clone().into_owned())
}
fn client_credentials(headers: &HeaderMap, request: &TokenRequest) -> Result<ClientCredentials> {
    if let Some(authorization) = headers.get(header::AUTHORIZATION) {
        if headers.get_all(header::AUTHORIZATION).iter().count() != 1
            || request.client_secret.is_some()
        {
            return Err(Error::InvalidClient);
        }
        let (scheme, encoded) = authorization
            .to_str()
            .map_err(|_| Error::InvalidClient)?
            .split_once(' ')
            .ok_or(Error::InvalidClient)?;
        if !scheme.eq_ignore_ascii_case("Basic") {
            return Err(Error::InvalidClient);
        }
        let bytes = STANDARD.decode(encoded).map_err(|_| Error::InvalidClient)?;
        let decoded = String::from_utf8(bytes).map_err(|_| Error::InvalidClient)?;
        let (id, secret) = decoded.split_once(':').ok_or(Error::InvalidClient)?;
        let client_id = decode_basic_component(id)?;
        if request
            .client_id
            .as_ref()
            .is_some_and(|body_id| body_id != &client_id)
        {
            return Err(Error::InvalidClient);
        }
        Ok(ClientCredentials {
            client_id,
            secret: Some(decode_basic_component(secret)?),
            authenticated_method: true,
        })
    } else {
        Ok(ClientCredentials {
            client_id: request.client_id.clone().ok_or(Error::InvalidClient)?,
            secret: request.client_secret.clone(),
            authenticated_method: request.client_secret.is_some(),
        })
    }
}
struct PasswordVerifier<'a>(&'a AppState);
#[async_trait]
impl SecretVerifier for PasswordVerifier<'_> {
    async fn verify(&self, secret: String, hash: String) -> Result<bool> {
        auth::verify_password(self.0, secret, hash)
            .await
            .map_err(|_| Error::Dependency)
    }
}
async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: std::result::Result<Form<TokenRequest>, FormRejection>,
) -> std::result::Result<Response, HttpError> {
    let Form(request) = request.map_err(|_| Error::InvalidRequest)?;
    let credentials = client_credentials(&headers, &request)?;
    let store = PgGrantStore::new(state.db.clone(), state.crypto.clone());
    let service = OAuth::new(&store, &state.crypto, &state.config.issuer);
    let client = service
        .authenticate_client(credentials, &PasswordVerifier(&state))
        .await?;
    let response = match request.grant_type.as_str() {
        "authorization_code" => {
            service
                .exchange_code(
                    &client,
                    request.code.as_deref().ok_or(Error::InvalidRequest)?,
                    request
                        .redirect_uri
                        .as_deref()
                        .ok_or(Error::InvalidRequest)?,
                    request
                        .code_verifier
                        .as_deref()
                        .ok_or(Error::InvalidRequest)?,
                )
                .await?
        }
        "refresh_token" => {
            service
                .exchange_refresh(
                    &client,
                    request
                        .refresh_token
                        .as_deref()
                        .ok_or(Error::InvalidRequest)?,
                    request.scope.as_deref(),
                )
                .await?
        }
        _ => return Err(Error::UnsupportedGrantType.into()),
    };
    let mut response = Json(response).into_response();
    no_store(&mut response);
    Ok(response)
}
async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> std::result::Result<Response, HttpError> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(Error::InvalidToken)?;
    let (scheme, token) = authorization.split_once(' ').ok_or(Error::InvalidToken)?;
    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
        return Err(Error::InvalidToken.into());
    }
    let claims = state
        .crypto
        .verify(token)
        .map_err(|_| Error::InvalidToken)?;
    let mut bearer_headers = HeaderMap::new();
    bearer_headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| Error::InvalidToken)?,
    );
    let actor = auth::authenticate_oidc(&state, &bearer_headers)
        .await
        .map_err(|error| {
            if error.status == StatusCode::SERVICE_UNAVAILABLE {
                Error::Dependency
            } else {
                Error::InvalidToken
            }
        })?;
    let info = application::userinfo(
        &claims,
        Subject {
            user_id: actor.user_id,
            session_id: actor.session_id,
        },
        &actor.email,
        actor.is_verified,
    )?;
    let mut response = Json(info).into_response();
    no_store(&mut response);
    Ok(response)
}

async fn consent_get(
    State(s): State<AppState>,
    h: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
) -> crate::ApiResult<Json<Value>> {
    use sqlx::Row;
    let a = auth::authenticate(&s, &h).await?;
    let row=sqlx::query("SELECT c.client_name,r.scopes,r.expires_at FROM oauth_consent_requests r JOIN oauth_clients c ON c.client_id=r.client_id WHERE r.id=$1 AND r.user_id=$2 AND r.session_id=$3 AND r.consumed_at IS NULL AND r.expires_at>now() AND c.revoked_at IS NULL").bind(id).bind(a.user_id).bind(a.session_id).fetch_optional(&s.db).await?.ok_or_else(||crate::ApiError::bad("consent_unavailable"))?;
    Ok(Json(
        json!({"request_id":id,"client_name":row.get::<String,_>("client_name"),"scopes":row.get::<Vec<String>,_>("scopes"),"expires_at":row.get::<chrono::DateTime<chrono::Utc>,_>("expires_at")}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsentDecision {
    approved: bool,
}
async fn consent_decide(
    State(s): State<AppState>,
    h: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
    Json(b): Json<ConsentDecision>,
) -> crate::ApiResult<Json<Value>> {
    let a = auth::mutation(&s, &h).await?;
    let mut tx = s.db.begin().await?;
    auth::lock_authorized_actor(&mut tx, &a, false, None).await?;
    let changed=sqlx::query("UPDATE oauth_consent_requests SET approved=$4 WHERE id=$1 AND user_id=$2 AND session_id=$3 AND consumed_at IS NULL AND approved IS NULL AND expires_at>now()").bind(id).bind(a.user_id).bind(a.session_id).bind(b.approved).execute(&mut *tx).await?;
    if changed.rows_affected() != 1 {
        return Err(crate::ApiError::bad("consent_unavailable"));
    }
    tx.commit().await?;
    Ok(Json(
        json!({"redirect_to":format!("/oauth/consent/complete/{id}")}),
    ))
}
async fn consent_complete(
    State(s): State<AppState>,
    h: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
) -> crate::ApiResult<Response> {
    use sqlx::Row;
    let a = auth::authenticate(&s, &h).await?;
    let mut tx = s.db.begin().await?;
    let client_id: Option<String> = sqlx::query_scalar(
        "SELECT client_id FROM oauth_consent_requests WHERE id=$1 AND user_id=$2 AND session_id=$3",
    )
    .bind(id)
    .bind(a.user_id)
    .bind(a.session_id)
    .fetch_optional(&mut *tx)
    .await?;
    let client_id = client_id.ok_or_else(|| crate::ApiError::bad("consent_unavailable"))?;
    sqlx::query(
        "SELECT client_id FROM oauth_clients WHERE client_id=$1 AND revoked_at IS NULL FOR UPDATE",
    )
    .bind(&client_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| crate::ApiError::bad("consent_unavailable"))?;
    auth::lock_authorized_actor(&mut tx, &a, false, None).await?;
    let row=sqlx::query("SELECT request,approved,client_id,scopes FROM oauth_consent_requests WHERE id=$1 AND user_id=$2 AND session_id=$3 AND consumed_at IS NULL AND expires_at>now() AND approved IS NOT NULL FOR UPDATE").bind(id).bind(a.user_id).bind(a.session_id).fetch_optional(&mut *tx).await?.ok_or_else(||crate::ApiError::bad("consent_unavailable"))?;
    let request: AuthorizeRequest =
        serde_json::from_value(row.get("request")).map_err(|_| crate::ApiError::dependency())?;
    let store = PgGrantStore::new(s.db.clone(), s.crypto.clone());
    let service = OAuth::new(&store, &s.crypto, &s.config.issuer);
    let approved = service
        .authorization(
            &request.client_id,
            Authorization {
                redirect_uri: &request.redirect_uri,
                response_type: &request.response_type,
                response_mode: request.response_mode.as_deref(),
                prompt: request.prompt.as_deref(),
                scope: &request.scope,
                nonce: request.nonce.as_deref(),
                challenge: request.code_challenge.as_deref(),
                challenge_method: request.code_challenge_method.as_deref(),
            },
        )
        .await
        .map_err(|_| crate::ApiError::bad("consent_unavailable"))?;
    let response = if row.get::<bool, _>("approved") {
        let scopes: Vec<String> = row.get("scopes");
        sqlx::query("INSERT INTO oauth_consents(user_id,client_id,scopes) VALUES($1,$2,$3) ON CONFLICT(user_id,client_id) DO UPDATE SET scopes=ARRAY(SELECT DISTINCT unnest(oauth_consents.scopes||EXCLUDED.scopes)),updated_at=now()").bind(a.user_id).bind(&request.client_id).bind(scopes).execute(&mut *tx).await?;
        let code = crate::security::random_token();
        let changed=sqlx::query("INSERT INTO oauth_authorization_codes(code_hash,client_id,session_id,user_id,redirect_uri,scope,nonce,code_challenge,expires_at) SELECT $1,$2,s.id,s.user_id,$5,$6,$7,$8,LEAST(now()+interval '120 seconds',s.expires_at) FROM sessions s JOIN oauth_clients c ON c.client_id=$2 AND c.revoked_at IS NULL WHERE s.id=$3 AND s.user_id=$4 AND s.is_active AND s.expires_at>now()")
            .bind(crate::security::digest(&code)).bind(&request.client_id).bind(a.session_id).bind(a.user_id).bind(&request.redirect_uri).bind(&request.scope).bind(&request.nonce).bind(request.code_challenge.as_deref().ok_or_else(||crate::ApiError::bad("invalid_request"))?).execute(&mut *tx).await?;
        if changed.rows_affected() != 1 {
            return Err(crate::ApiError::unauthorized());
        }
        redirect(approved.redirect, request.state.as_deref(), "code", &code)
    } else {
        redirect(
            approved.redirect,
            request.state.as_deref(),
            "error",
            "access_denied",
        )
    };
    sqlx::query("UPDATE oauth_consent_requests SET consumed_at=now() WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(response)
}
