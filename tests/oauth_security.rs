use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use identity_service::{
    auth,
    config::Config,
    oauth,
    security::{digest, random_token},
    AppState,
};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

const CALLBACK: &str = "https://localhost:8448/oidc/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Fixture {
    state: AppState,
    app: Router,
    cookie: String,
    sid: Uuid,
    uid: Uuid,
}

impl Fixture {
    async fn new() -> Self {
        let database_url =
            std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL is required");
        let schema = format!("oauth_test_{}", Uuid::new_v4().simple());
        let setup = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .unwrap();
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&setup)
            .await
            .unwrap();
        let db = PgPoolOptions::new()
            .max_connections(5)
            .after_connect(move |conn, _| {
                let command = format!("SET search_path TO {schema}");
                Box::pin(async move {
                    sqlx::query(&command).execute(conn).await?;
                    Ok(())
                })
            })
            .connect(&database_url)
            .await
            .unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        let mut config =
            Config::from_env().expect("real RSA signing/encryption environment is required");
        config.database_url = database_url;
        let mut state = AppState::connect(config).await.unwrap();
        state.db = db;
        let uid = Uuid::new_v4();
        let sid = Uuid::new_v4();
        let cookie = random_token();
        sqlx::query("INSERT INTO users(id,email,password_hash,is_verified) VALUES($1,$2,'unused-test-password',true)")
            .bind(uid).bind(format!("{uid}@example.test")).execute(&state.db).await.unwrap();
        sqlx::query("INSERT INTO sessions(id,user_id,ip_address,user_agent,cookie_hash,csrf_hash,expires_at) VALUES($1,$2,'127.0.0.1','oauth-regression',$3,$4,NOW()+INTERVAL '1 day')")
            .bind(sid).bind(uid).bind(digest(&cookie)).bind(digest(&random_token())).execute(&state.db).await.unwrap();
        let app = oauth::router(state.clone());
        Self {
            state,
            app,
            cookie,
            sid,
            uid,
        }
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: String,
        credential: Option<(&str, &str)>,
    ) -> (StatusCode, axum::http::HeaderMap, Value) {
        let mut request = Request::builder().method(method).uri(path);
        if method == "POST" {
            request = request.header("content-type", "application/x-www-form-urlencoded");
        }
        if let Some((header, value)) = credential {
            request = request.header(header, value);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        (
            status,
            headers,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    fn authorize_path(&self, redirect: &str, scope: &str) -> String {
        format!(
            "/oauth/authorize?{}",
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("client_id", "web-demo"),
                    ("response_type", "code"),
                    ("redirect_uri", redirect),
                    ("scope", scope),
                    ("state", "state +&=?"),
                    ("nonce", "nonce +&=?"),
                    ("code_challenge", CHALLENGE),
                    ("code_challenge_method", "S256")
                ])
                .finish()
        )
    }

    async fn code(&self, scope: &str) -> String {
        let cookie = format!("sso_session={}", self.cookie);
        let (status, headers, _) = self
            .request(
                "GET",
                &self.authorize_path(CALLBACK, scope),
                String::new(),
                Some(("cookie", &cookie)),
            )
            .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let redirect = url::Url::parse(headers["location"].to_str().unwrap()).unwrap();
        assert_eq!(
            redirect
                .query_pairs()
                .find(|(key, _)| key == "state")
                .unwrap()
                .1,
            "state +&=?"
        );
        redirect
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned()
    }

    async fn exchange(&self, code: &str, verifier: &str, redirect: &str) -> (StatusCode, Value) {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "authorization_code"),
                ("client_id", "web-demo"),
                ("code", code),
                ("code_verifier", verifier),
                ("redirect_uri", redirect),
            ])
            .finish();
        let (status, headers, value) = self.request("POST", "/oauth/token", body, None).await;
        assert_eq!(headers["cache-control"], "no-store");
        (status, value)
    }

    async fn refresh(&self, token: &str) -> (StatusCode, Value) {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "refresh_token"),
                ("client_id", "web-demo"),
                ("refresh_token", token),
            ])
            .finish();
        let (status, _, value) = self.request("POST", "/oauth/token", body, None).await;
        (status, value)
    }

    async fn userinfo(&self, token: &str) -> (StatusCode, Value) {
        let authorization = format!("Bearer {token}");
        let (status, _, value) = self
            .request(
                "GET",
                "/oauth/userinfo",
                String::new(),
                Some(("authorization", &authorization)),
            )
            .await;
        (status, value)
    }
}

#[tokio::test]
#[ignore = "requires real TEST_DATABASE_URL and RSA signing/encryption environment"]
async fn discovery_pkce_rs256_nonce_and_scope_claims_are_standard() {
    let f = Fixture::new().await;
    let (status, _, discovery) = f
        .request(
            "GET",
            "/.well-known/openid-configuration",
            String::new(),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        discovery["id_token_signing_alg_values_supported"],
        json!(["RS256"])
    );
    assert_eq!(
        discovery["code_challenge_methods_supported"],
        json!(["S256"])
    );
    assert_eq!(
        discovery["grant_types_supported"],
        json!(["authorization_code", "refresh_token"])
    );
    let code = f.code("openid email profile offline_access").await;
    let (status, tokens) = f.exchange(&code, VERIFIER, CALLBACK).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tokens["token_type"], "Bearer");
    assert!(tokens["expires_in"].as_u64().unwrap() > 0);
    let jwks = f.state.crypto.jwks();
    let key = &jwks["keys"][0];
    let decoding = jsonwebtoken::DecodingKey::from_rsa_components(
        key["n"].as_str().unwrap(),
        key["e"].as_str().unwrap(),
    )
    .unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&["web-demo"]);
    validation.set_issuer(&[f.state.config.issuer.as_str()]);
    let claims =
        jsonwebtoken::decode::<Value>(tokens["id_token"].as_str().unwrap(), &decoding, &validation)
            .unwrap()
            .claims;
    assert_eq!(claims["sub"], f.uid.to_string());
    assert_eq!(claims["nonce"], "nonce +&=?");
    assert_eq!(claims["email_verified"], true);
    let (status, info) = f.userinfo(tokens["access_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(info["sub"], f.uid.to_string());
    assert!(info["email"].is_string());
    assert!(
        info["name"].is_null(),
        "identity does not own a profile name"
    );
}

#[tokio::test]
#[ignore = "requires real TEST_DATABASE_URL and RSA signing/encryption environment"]
async fn anonymous_authorization_preserves_encoded_return_path_and_never_redirects_to_unregistered_uri(
) {
    let f = Fixture::new().await;
    let path = f.authorize_path(CALLBACK, "openid");
    let (status, headers, _) = f.request("GET", &path, String::new(), None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = headers["location"].to_str().unwrap();
    let location = url::Url::parse(&format!("https://localhost:8448{location}")).unwrap();
    assert_eq!(location.path(), "/");
    assert_eq!(
        location
            .query_pairs()
            .find(|(k, _)| k == "return_to")
            .unwrap()
            .1,
        path
    );
    for redirect in [
        "https://localhost:8448/oidc/callback/",
        "https://attacker.test/oidc/callback",
        "https://localhost:8448/oidc/callback?extra=1",
    ] {
        let (status, headers, body) = f
            .request(
                "GET",
                &f.authorize_path(redirect, "openid"),
                String::new(),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(headers.get("location").is_none());
        assert_eq!(body["error"], "invalid_request");
    }
}

#[tokio::test]
#[ignore = "requires real TEST_DATABASE_URL and RSA signing/encryption environment"]
async fn wrong_verifier_redirect_and_client_cannot_redeem_a_code() {
    let f = Fixture::new().await;
    let code = f.code("openid").await;
    for (verifier, redirect) in [
        ("wrong-verifier", CALLBACK),
        (VERIFIER, "https://attacker.test/callback"),
    ] {
        let (status, body) = f.exchange(&code, verifier, redirect).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
    }
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("client_id", "unknown-client"),
            ("code", code.as_str()),
            ("code_verifier", VERIFIER),
            ("redirect_uri", CALLBACK),
        ])
        .finish();
    let (status, _, body) = f.request("POST", "/oauth/token", body, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_client");
    let public_secret_form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("client_id", "web-demo"),
            ("client_secret", "must-not-be-accepted"),
            ("code", code.as_str()),
            ("code_verifier", VERIFIER),
            ("redirect_uri", CALLBACK),
        ])
        .finish();
    assert_eq!(
        f.request("POST", "/oauth/token", public_secret_form, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, tokens) = f.exchange(&code, VERIFIER, CALLBACK).await;
    assert_eq!(status, StatusCode::OK);
    assert!(tokens.get("refresh_token").is_none());
    let id_claims: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(
                tokens["id_token"]
                    .as_str()
                    .unwrap()
                    .split('.')
                    .nth(1)
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    assert!(id_claims.get("email").is_none());
    assert!(id_claims.get("email_verified").is_none());
    let (_, info) = f.userinfo(tokens["access_token"].as_str().unwrap()).await;
    assert!(info.get("email").is_none());
}

#[tokio::test]
#[ignore = "requires real TEST_DATABASE_URL and RSA signing/encryption environment"]
async fn authorization_code_replay_revokes_already_issued_access_and_refresh() {
    let f = Fixture::new().await;
    let code = f.code("openid offline_access").await;
    let (_, tokens) = f.exchange(&code, VERIFIER, CALLBACK).await;
    assert_eq!(
        f.userinfo(tokens["access_token"].as_str().unwrap()).await.0,
        StatusCode::OK
    );
    let (status, error) = f.exchange(&code, VERIFIER, CALLBACK).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["error"], "invalid_grant");
    assert_eq!(
        f.userinfo(tokens["access_token"].as_str().unwrap()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.refresh(tokens["refresh_token"].as_str().unwrap()).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
#[ignore = "requires real TEST_DATABASE_URL and RSA signing/encryption environment"]
async fn concurrent_refresh_has_one_winner_and_reuse_revokes_the_winning_branch() {
    let f = Fixture::new().await;
    let code = f.code("openid email offline_access").await;
    let (_, tokens) = f.exchange(&code, VERIFIER, CALLBACK).await;
    let refresh = tokens["refresh_token"].as_str().unwrap();
    let (first, second) = tokio::join!(f.refresh(refresh), f.refresh(refresh));
    assert_eq!(
        [first.0, second.0]
            .iter()
            .filter(|s| **s == StatusCode::OK)
            .count(),
        1
    );
    let winner = if first.0 == StatusCode::OK {
        first.1
    } else {
        second.1
    };
    assert_eq!(
        f.userinfo(winner["access_token"].as_str().unwrap()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.refresh(winner["refresh_token"].as_str().unwrap()).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
#[ignore = "requires real TEST_DATABASE_URL and RSA signing/encryption environment"]
async fn logout_and_user_ban_are_authoritative_for_access_and_refresh() {
    for ban in [false, true] {
        let f = Fixture::new().await;
        let code = f.code("openid offline_access").await;
        let (_, tokens) = f.exchange(&code, VERIFIER, CALLBACK).await;
        if ban {
            sqlx::query("UPDATE users SET is_banned=true WHERE id=$1")
                .bind(f.uid)
                .execute(&f.state.db)
                .await
                .unwrap();
        } else {
            sqlx::query("UPDATE sessions SET is_active=false WHERE id=$1")
                .bind(f.sid)
                .execute(&f.state.db)
                .await
                .unwrap();
        }
        assert_eq!(
            f.userinfo(tokens["access_token"].as_str().unwrap()).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            f.refresh(tokens["refresh_token"].as_str().unwrap()).await.0,
            StatusCode::BAD_REQUEST
        );
    }
}

#[tokio::test]
#[ignore = "requires real TEST_DATABASE_URL and RSA signing/encryption environment"]
async fn confidential_client_requires_a_hashed_secret_and_basic_authentication() {
    let f = Fixture::new().await;
    let secret = random_token();
    let hash = auth::hash_password(&f.state, secret.clone()).await.unwrap();
    sqlx::query("INSERT INTO oauth_clients(client_id,client_name,client_secret_hash,redirect_uris,allowed_scopes,is_public) VALUES('confidential','Regression client',$1,ARRAY[$2],ARRAY['openid'],false)")
        .bind(&hash).bind(CALLBACK).execute(&f.state.db).await.unwrap();
    assert_ne!(hash, secret);
    let cookie = format!("sso_session={}", f.cookie);
    let path = f
        .authorize_path(CALLBACK, "openid")
        .replace("client_id=web-demo", "client_id=confidential");
    let (_, headers, _) = f
        .request("GET", &path, String::new(), Some(("cookie", &cookie)))
        .await;
    let redirect = url::Url::parse(headers["location"].to_str().unwrap()).unwrap();
    let code = redirect
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("code_verifier", VERIFIER),
            ("redirect_uri", CALLBACK),
            ("client_id", "confidential"),
        ])
        .finish();
    let (status, _, error) = f.request("POST", "/oauth/token", form.clone(), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error["error"], "invalid_client");
    let bad_authorization = format!("Basic {}", STANDARD.encode("confidential:wrong-secret"));
    assert_eq!(
        f.request(
            "POST",
            "/oauth/token",
            form.clone(),
            Some(("authorization", &bad_authorization))
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let authorization = format!(
        "Basic {}",
        STANDARD.encode(format!("confidential:{secret}"))
    );
    let (status, _, tokens) = f
        .request(
            "POST",
            "/oauth/token",
            form,
            Some(("authorization", &authorization)),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(tokens["id_token"].is_string());
    let (_, headers, _) = f
        .request("GET", &path, String::new(), Some(("cookie", &cookie)))
        .await;
    let redirect = url::Url::parse(headers["location"].to_str().unwrap()).unwrap();
    let post_code = redirect
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned();
    let form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("code", post_code.as_str()),
            ("code_verifier", VERIFIER),
            ("redirect_uri", CALLBACK),
            ("client_id", "confidential"),
            ("client_secret", secret.as_str()),
        ])
        .finish();
    let (status, _, tokens) = f.request("POST", "/oauth/token", form, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(tokens["id_token"].is_string());
}

#[tokio::test]
#[ignore = "requires real TEST_DATABASE_URL and RSA signing/encryption environment"]
async fn refresh_scope_reduction_cannot_expand_on_a_later_rotation() {
    let f = Fixture::new().await;
    let code = f.code("openid email offline_access").await;
    let (_, tokens) = f.exchange(&code, VERIFIER, CALLBACK).await;
    let form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "refresh_token"),
            ("client_id", "web-demo"),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("scope", "openid"),
        ])
        .finish();
    let (status, _, reduced) = f.request("POST", "/oauth/token", form, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reduced["scope"], "openid");
    let (status, next) = f.refresh(reduced["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(next["scope"], "openid");
    let (_, info) = f.userinfo(next["access_token"].as_str().unwrap()).await;
    assert!(info.get("email").is_none());
}

#[tokio::test]
#[ignore = "requires real TEST_DATABASE_URL and RSA signing/encryption environment"]
async fn concurrent_code_exchange_has_one_winner_and_replay_invalidates_its_access() {
    let f = Fixture::new().await;
    let code = f.code("openid").await;
    let (first, second) = tokio::join!(
        f.exchange(&code, VERIFIER, CALLBACK),
        f.exchange(&code, VERIFIER, CALLBACK)
    );
    assert_eq!(
        [first.0, second.0]
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1
    );
    let winner = if first.0 == StatusCode::OK {
        first.1
    } else {
        second.1
    };
    assert_eq!(
        f.userinfo(winner["access_token"].as_str().unwrap()).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
#[ignore = "requires real TEST_DATABASE_URL and RSA signing/encryption environment"]
async fn authorize_rejects_plain_pkce_and_unregistered_scopes_with_encoded_state() {
    let f = Fixture::new().await;
    let cookie = format!("sso_session={}", f.cookie);
    for (path, error) in [
        (
            f.authorize_path(CALLBACK, "openid")
                .replace("code_challenge_method=S256", "code_challenge_method=plain"),
            "invalid_request",
        ),
        (
            f.authorize_path(CALLBACK, "openid administrator"),
            "invalid_scope",
        ),
    ] {
        let (status, headers, _) = f
            .request("GET", &path, String::new(), Some(("cookie", &cookie)))
            .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let redirect = url::Url::parse(headers["location"].to_str().unwrap()).unwrap();
        assert_eq!(
            redirect
                .query_pairs()
                .find(|(k, _)| k == "error")
                .unwrap()
                .1,
            error
        );
        assert_eq!(
            redirect
                .query_pairs()
                .find(|(k, _)| k == "state")
                .unwrap()
                .1,
            "state +&=?"
        );
    }
}

#[tokio::test]
#[ignore = "requires real TEST_DATABASE_URL and RSA signing/encryption environment"]
async fn expired_codes_and_id_tokens_cannot_authenticate_and_bearer_credentials_are_hashed_at_rest()
{
    let f = Fixture::new().await;
    let expired = f.code("openid").await;
    sqlx::query("UPDATE oauth_authorization_codes SET expires_at=NOW()-INTERVAL '1 second' WHERE code_hash=$1")
        .bind(digest(&expired)).execute(&f.state.db).await.unwrap();
    assert_eq!(
        f.exchange(&expired, VERIFIER, CALLBACK).await.0,
        StatusCode::BAD_REQUEST
    );
    let code = f.code("openid offline_access").await;
    let (status, tokens) = f.exchange(&code, VERIFIER, CALLBACK).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        f.userinfo(tokens["id_token"].as_str().unwrap()).await.0,
        StatusCode::UNAUTHORIZED
    );
    let stored_code: String =
        sqlx::query_scalar("SELECT code_hash FROM oauth_authorization_codes WHERE code_hash=$1")
            .bind(digest(&code))
            .fetch_one(&f.state.db)
            .await
            .unwrap();
    assert_ne!(stored_code, code);
    let refresh = tokens["refresh_token"].as_str().unwrap();
    let stored_refresh: String =
        sqlx::query_scalar("SELECT token_hash FROM oauth_refresh_tokens WHERE token_hash=$1")
            .bind(digest(refresh))
            .fetch_one(&f.state.db)
            .await
            .unwrap();
    assert_ne!(stored_refresh, refresh);
}

#[tokio::test]
#[ignore = "requires real TEST_DATABASE_URL and RSA signing/encryption environment"]
async fn legacy_http_registration_is_retained_but_cannot_receive_authorization_codes() {
    let f = Fixture::new().await;
    let legacy_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM oauth_clients WHERE client_id='trade_helper_frontend')",
    )
    .fetch_one(&f.state.db)
    .await
    .unwrap();
    assert!(
        legacy_exists,
        "historical registration data must not be deleted"
    );
    let path = f
        .authorize_path("http://localhost:3000/callback", "openid")
        .replace("client_id=web-demo", "client_id=trade_helper_frontend");
    let cookie = format!("sso_session={}", f.cookie);
    let (status, headers, body) = f
        .request("GET", &path, String::new(), Some(("cookie", &cookie)))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(headers.get("location").is_none());
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
#[ignore = "requires real TEST_DATABASE_URL and RSA signing/encryption environment"]
async fn authorization_and_refresh_for_the_same_session_do_not_deadlock() {
    let f = Fixture::new().await;
    let first_code = f.code("openid offline_access").await;
    let (_, tokens) = f.exchange(&first_code, VERIFIER, CALLBACK).await;
    let next_code = f.code("openid offline_access").await;
    let refresh = tokens["refresh_token"].as_str().unwrap();
    let (code_result, refresh_result) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                f.exchange(&next_code, VERIFIER, CALLBACK),
                f.refresh(refresh)
            )
        })
        .await
        .expect("all grant mutations must lock user, session, then grant rows");
    assert_eq!(code_result.0, StatusCode::OK);
    assert_eq!(refresh_result.0, StatusCode::OK);
}

#[tokio::test]
#[ignore = "requires real TEST_DATABASE_URL and RSA signing/encryption environment"]
async fn spent_code_without_bound_pkce_and_redirect_cannot_revoke_victim_session() {
    let f = Fixture::new().await;
    let code = f.code("openid offline_access").await;
    let (status, tokens) = f.exchange(&code, VERIFIER, CALLBACK).await;
    assert_eq!(status, StatusCode::OK);
    for (verifier, redirect) in [
        ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CALLBACK),
        (VERIFIER, "https://attacker.invalid/callback"),
    ] {
        let (status, _) = f.exchange(&code, verifier, redirect).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let live: bool = sqlx::query_scalar("SELECT is_active FROM sessions WHERE id=$1")
            .bind(f.sid)
            .fetch_one(&f.state.db)
            .await
            .unwrap();
        assert!(live);
        let revoked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oauth_token_families WHERE session_id=$1 AND revoked_at IS NOT NULL)").bind(f.sid).fetch_one(&f.state.db).await.unwrap();
        assert!(!revoked);
    }
    let (status, _) = f.refresh(tokens["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK);
}
