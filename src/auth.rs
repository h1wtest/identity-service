mod internal;
mod mfa;
mod password;
use crate::{
    events::enqueue,
    security::{constant_eq, digest, random_token},
    ApiError, ApiResult, AppState,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct Actor {
    pub user_id: Uuid,
    pub email: String,
    pub session_id: Uuid,
    pub mfa_verified: bool,
    pub is_verified: bool,
    pub mfa_enabled: bool,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}
pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get("cookie")?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned())
}
fn trace(headers: &HeaderMap) -> Option<&str> {
    headers.get("traceparent").and_then(|v| v.to_str().ok())
}
pub async fn authenticate(state: &AppState, headers: &HeaderMap) -> ApiResult<Actor> {
    authenticate_for(state, headers, false).await
}
pub(crate) async fn authenticate_oidc(state: &AppState, headers: &HeaderMap) -> ApiResult<Actor> {
    authenticate_for(state, headers, true).await
}
async fn authenticate_for(
    state: &AppState,
    headers: &HeaderMap,
    oidc_userinfo: bool,
) -> ApiResult<Actor> {
    let (sid, uid, cookie_hash) = if let Some(authorization) = headers.get("authorization") {
        let token = authorization
            .to_str()
            .ok()
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|v| !v.is_empty())
            .ok_or_else(ApiError::unauthorized)?;
        let claims = state.crypto.verify(token)?;
        if oidc_userinfo {
            let grant_id = claims.grant_id.ok_or_else(ApiError::unauthorized)?;
            let client:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oauth_token_families f JOIN oauth_clients c ON c.client_id=f.client_id WHERE f.id=$1 AND f.client_id=$2 AND f.user_id=$3 AND f.session_id=$4 AND f.revoked_at IS NULL AND f.expires_at>now() AND c.revoked_at IS NULL)").bind(grant_id).bind(&claims.aud).bind(claims.sub).bind(claims.sid).fetch_one(&state.db).await?;
            if !client
                || !claims
                    .scope
                    .split_whitespace()
                    .any(|scope| scope == "openid")
            {
                return Err(ApiError::unauthorized());
            }
        } else if claims.aud != state.config.public_origin
            || !claims
                .scope
                .split_whitespace()
                .any(|scope| scope == "platform:api")
        {
            return Err(ApiError::unauthorized());
        }
        (Some(claims.sid), Some(claims.sub), None)
    } else {
        let token = cookie(headers, "sso_session").ok_or_else(ApiError::unauthorized)?;
        (None, None, Some(digest(&token)))
    };
    let row=sqlx::query("SELECT u.id,u.email,u.is_verified,s.id AS sid,s.mfa_verified,s.mfa_verified_at,COALESCE(m.is_enabled,false) AS mfa_enabled FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN mfa_secrets m ON m.user_id=u.id WHERE s.is_active AND s.expires_at>now() AND NOT u.is_banned AND (($1::uuid IS NOT NULL AND s.id=$1 AND u.id=$2) OR ($3::text IS NOT NULL AND s.cookie_hash=$3))")
 .bind(sid).bind(uid).bind(cookie_hash).fetch_optional(&state.db).await?.ok_or_else(ApiError::unauthorized)?;
    let user_id: Uuid = row.get("id");
    let session_id: Uuid = row.get("sid");
    let roles:Vec<String>=sqlx::query_scalar("SELECT r.slug FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1 AND (ur.expires_at IS NULL OR ur.expires_at>now()) ORDER BY r.slug").bind(user_id).fetch_all(&state.db).await?;
    let mut permissions:Vec<String>=sqlx::query_scalar("SELECT DISTINCT p.slug FROM user_roles ur JOIN role_permissions rp ON rp.role_id=ur.role_id JOIN permissions p ON p.id=rp.permission_id WHERE ur.user_id=$1 AND (ur.expires_at IS NULL OR ur.expires_at>now()) ORDER BY p.slug").bind(user_id).fetch_all(&state.db).await?;
    permissions.retain(|p| {
        crate::rbac::PERMISSIONS.contains(&p.as_str())
            && (!crate::rbac::owner_only(p) || roles.iter().any(|r| r == "owner"))
    });
    permissions.extend(crate::rbac::OWN_PERMISSIONS.iter().map(|p| p.to_string()));
    let mfa_verified = row.get::<bool, _>("mfa_verified")
        && row
            .get::<Option<DateTime<Utc>>, _>("mfa_verified_at")
            .map(|t| t > Utc::now() - chrono::Duration::minutes(15))
            .unwrap_or(false);
    Ok(Actor {
        user_id,
        email: row.get("email"),
        session_id,
        is_verified: row.get("is_verified"),
        mfa_enabled: row.get("mfa_enabled"),
        mfa_verified,
        roles,
        permissions,
    })
}
pub fn require_permission(actor: &Actor, permission: &str) -> ApiResult<()> {
    if !crate::rbac::known_permission(permission)
        || (crate::rbac::owner_only(permission) && !actor.roles.iter().any(|r| r == "owner"))
        || !actor.mfa_enabled
        || !actor.mfa_verified
        || !actor.permissions.iter().any(|v| v == permission)
    {
        Err(ApiError::forbidden())
    } else {
        Ok(())
    }
}
pub fn csrf(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    if headers.get("origin").and_then(|v| v.to_str().ok())
        != Some(state.config.public_origin.as_str())
    {
        return Err(ApiError::forbidden());
    }
    let token = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(ApiError::forbidden)?;
    let value = cookie(headers, "sso_csrf").ok_or_else(ApiError::forbidden)?;
    if token.len() < 32 || !constant_eq(token, &value) {
        return Err(ApiError::forbidden());
    }
    Ok(())
}
pub(crate) async fn mutation(state: &AppState, headers: &HeaderMap) -> ApiResult<Actor> {
    if cookie(headers, "sso_session").is_none()
        && headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.starts_with("Bearer "))
            .unwrap_or(false)
    {
        return authenticate(state, headers).await;
    }
    csrf(state, headers)?;
    let actor = authenticate(state, headers).await?;
    let hash: Option<String> =
        sqlx::query_scalar("SELECT csrf_hash FROM sessions WHERE id=$1 AND is_active")
            .bind(actor.session_id)
            .fetch_optional(&state.db)
            .await?
            .flatten();
    let csrf = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !hash
        .map(|h| constant_eq(&h, &digest(csrf)))
        .unwrap_or(false)
    {
        return Err(ApiError::forbidden());
    }
    Ok(actor)
}

pub async fn lock_authorized_actor(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    require_reauth: bool,
    permission: Option<&str>,
) -> ApiResult<()> {
    let mut store =
        crate::adapters::postgres::security::PostgresSecurityTransaction { transaction: tx };
    crate::application::security::authorize(
        &mut store,
        actor.user_id,
        actor.session_id,
        crate::domain::security::AuthorizationRequirement {
            fresh_password: require_reauth,
            permission,
        },
    )
    .await
}
pub async fn hash_password(state: &AppState, password: String) -> ApiResult<String> {
    validate_password(&password)?;
    let permit = state
        .passwords
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| ApiError::dependency())?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        Argon2::default()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .map(|h| h.to_string())
            .map_err(|_| ApiError::dependency())
    })
    .await
    .map_err(|_| ApiError::dependency())?
}
pub async fn verify_password(state: &AppState, password: String, hash: String) -> ApiResult<bool> {
    if password.len() > 1024 {
        return Err(ApiError::bad("password_too_long"));
    }
    let permit = state
        .passwords
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| ApiError::dependency())?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        Ok(PasswordHash::new(&hash)
            .map(|hash| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &hash)
                    .is_ok()
            })
            .unwrap_or(false))
    })
    .await
    .map_err(|_| ApiError::dependency())?
}
fn validate_password(password: &str) -> ApiResult<()> {
    if !(12..=1024).contains(&password.len()) {
        Err(ApiError::bad("password_length"))
    } else {
        Ok(())
    }
}
fn email(value: &str) -> ApiResult<String> {
    let value = value.trim().to_lowercase();
    if value.len() > 254
        || value.contains(char::is_whitespace)
        || !value
            .split_once('@')
            .map(|(a, b)| !a.is_empty() && b.contains('.') && !b.ends_with('.'))
            .unwrap_or(false)
    {
        return Err(ApiError::bad("invalid_email"));
    }
    Ok(value)
}
async fn rate(state: &AppState, kind: &str, key: &str, limit: i32) -> ApiResult<()> {
    let count:i32=sqlx::query_scalar("INSERT INTO identity_rate_limits(bucket,window_start,attempts) VALUES($1,now(),1) ON CONFLICT(bucket) DO UPDATE SET attempts=CASE WHEN identity_rate_limits.window_start<now()-interval '10 minutes' THEN 1 ELSE identity_rate_limits.attempts+1 END,window_start=CASE WHEN identity_rate_limits.window_start<now()-interval '10 minutes' THEN now() ELSE identity_rate_limits.window_start END RETURNING attempts").bind(format!("{kind}:{}",digest(key))).fetch_one(&state.db).await?;
    if count > limit {
        Err(ApiError::limited())
    } else {
        Ok(())
    }
}
fn agent(headers: &HeaderMap) -> String {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .chars()
        .take(512)
        .collect()
}
fn ip(headers: &HeaderMap) -> String {
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.parse::<std::net::IpAddr>().is_ok())
        .unwrap_or("unknown")
        .to_owned()
}
fn response_with_cookies(
    status: StatusCode,
    body: Value,
    session: Option<&str>,
    csrf: &str,
    ttl: i64,
) -> Response {
    let mut response = (status, Json(body)).into_response();
    if let Some(token) = session {
        response.headers_mut().append(
            "set-cookie",
            HeaderValue::from_str(&format!(
                "sso_session={token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={ttl}"
            ))
            .expect("random cookie safe"),
        );
    }
    response.headers_mut().append(
        "set-cookie",
        HeaderValue::from_str(&format!(
            "sso_csrf={csrf}; Path=/; Secure; SameSite=Lax; Max-Age={ttl}"
        ))
        .expect("random cookie safe"),
    );
    response
}
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/auth/csrf", get(get_csrf))
        .route("/api/v1/auth/register", post(register))
        .route("/api/v1/auth/verify-email", post(verify_email))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/me", get(me))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/sessions", get(sessions).delete(revoke_all))
        .route("/api/v1/auth/sessions/{id}", delete(revoke))
        .route("/api/v1/auth/sessions/revoke-others", post(revoke_others))
        .route("/api/v1/auth/reauth", post(mfa::reauth))
        .route("/api/v1/auth/mfa/setup", post(mfa::setup))
        .route("/api/v1/auth/mfa/enable", post(mfa::enable))
        .route("/api/v1/auth/mfa/disable", post(mfa::disable))
        .route("/api/v1/auth/mfa/verify-login", post(mfa::login))
        .route("/api/v1/auth/password/forgot", post(password::forgot))
        .route("/api/v1/auth/password/reset", post(password::reset))
        .route("/api/v1/auth/password/change", post(password::change))
        .route("/internal/v1/introspect", post(internal::introspect))
        .route("/internal/v2/introspect", post(internal::introspect_v2))
        .route("/internal/v2/users", get(internal::backfill))
        .route(
            "/internal/v2/users/{id}/eligibility",
            get(internal::eligibility),
        )
        .route(
            "/internal/v2/users/{id}/notification-flow",
            get(internal::notification_flow),
        )
        .route("/internal/v2/admin/users", get(internal::users))
        .route("/internal/v2/admin/users/{id}/ban", post(internal::ban_v2))
        .route(
            "/internal/v2/admin/users/{id}/unban",
            post(internal::unban_v2),
        )
        .route(
            "/internal/v2/admin/users/{id}/sessions/revoke",
            post(internal::revoke_v2),
        )
        .route("/internal/v2/admin/users/{id}", get(internal::user_detail))
        .route(
            "/internal/v2/admin/commands/{id}",
            get(internal::command_status),
        )
        .route(
            "/internal/v2/notification-recipients",
            get(internal::notification_recipients),
        )
        .route(
            "/api/v1/admin/users/{id}/sessions/revoke",
            post(internal::admin_revoke_public),
        )
        .route("/internal/v1/admin/users", get(internal::users))
        .route("/internal/v1/admin/users/{id}/ban", post(internal::ban))
        .route("/internal/v1/admin/users/{id}/unban", post(internal::unban))
        .with_state(state)
}
async fn get_csrf(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    let token = cookie(&headers, "sso_csrf")
        .filter(|t| t.len() == 43)
        .unwrap_or_else(random_token);
    if let Ok(actor) = authenticate(&state, &headers).await {
        sqlx::query("UPDATE sessions SET csrf_hash=$1 WHERE id=$2 AND is_active")
            .bind(digest(&token))
            .bind(actor.session_id)
            .execute(&state.db)
            .await?;
    }
    Ok(response_with_cookies(
        StatusCode::OK,
        json!({"csrf_token":token}),
        None,
        &token,
        state.config.session_ttl_seconds,
    ))
}
#[derive(Deserialize)]
struct Register {
    email: String,
    password: String,
    locale: Option<String>,
    referral_code: Option<String>,
}
async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Register>,
) -> ApiResult<Response> {
    csrf(&state, &headers)?;
    let email = email(&body.email)?;
    rate(&state, "register", &ip(&headers), 20).await?;
    rate(&state, "register-email", &email, 5).await?;
    let hash = hash_password(&state, body.password).await?;
    let id = Uuid::now_v7();
    let registration_id = Uuid::now_v7();
    let locale = body.locale.unwrap_or_else(|| {
        if headers
            .get("accept-language")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .starts_with("ru")
        {
            "ru".into()
        } else {
            "en".into()
        }
    });
    if !["en", "ru"].contains(&locale.as_str()) {
        return Err(ApiError::bad("invalid_locale"));
    }
    let referral_claim =
        crate::referral::prepare(&state, id, registration_id, body.referral_code.as_deref())
            .await?;
    let referral_claim_id = referral_claim.as_ref().map(|(id, _)| *id);
    let code = format!("{:06}", rand::random::<u32>() % 1_000_000);
    let expires = Utc::now() + chrono::Duration::minutes(15);
    let mut tx = state.db.begin().await?;
    let result = sqlx::query(
        "INSERT INTO users(id,email,password_hash,registration_id,registration_locale,referral_claim_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(email) DO NOTHING",
    )
    .bind(id)
    .bind(&email)
    .bind(hash)
    .bind(registration_id).bind(&locale).bind(referral_claim_id)
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::bad("registration_unavailable"));
    }
    sqlx::query("INSERT INTO identity_challenges(id,user_id,kind,token_hash,expires_at) VALUES($1,$2,'verify_email',$3,$4)").bind(Uuid::new_v4()).bind(id).bind(digest(&format!("{id}:{code}"))).bind(expires).execute(&mut *tx).await?;
    crate::events::enqueue_registration(
        &mut tx,
        &state.crypto,
        id,
        json!({"user_id":id,"email":email,"locale":locale,"registration_id":registration_id,"referral_claim_id":referral_claim_id}),
        trace(&headers),
        referral_claim.as_ref().map(|(_,deadline)|*deadline),
    )
    .await?;
    enqueue(
        &mut tx,
        &state.crypto,
        "notification.email_verification",
        id,
        json!({"user_id":id,"email":email,"code":code,"expires_at":expires,"locale":locale}),
        trace(&headers),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"user_id":id,"email":email,"message":"Check your email"})),
    )
        .into_response())
}
#[derive(Deserialize)]
struct VerifyEmail {
    user_id: Uuid,
    code: String,
}
async fn verify_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<VerifyEmail>,
) -> ApiResult<Json<Value>> {
    csrf(&state, &headers)?;
    rate(&state, "verify", &body.user_id.to_string(), 10).await?;
    let mut tx = state.db.begin().await?;
    let allowed: Option<bool> =
        sqlx::query_scalar("SELECT NOT is_banned FROM users WHERE id=$1 FOR UPDATE")
            .bind(body.user_id)
            .fetch_optional(&mut *tx)
            .await?;
    if allowed != Some(true) {
        return Err(ApiError::bad("invalid_code"));
    }
    let changed=sqlx::query("UPDATE identity_challenges SET consumed_at=now() WHERE user_id=$1 AND kind='verify_email' AND token_hash=$2 AND consumed_at IS NULL AND expires_at>now()").bind(body.user_id).bind(digest(&format!("{}:{}",body.user_id,body.code))).execute(&mut *tx).await?;
    if changed.rows_affected() != 1 {
        return Err(ApiError::bad("invalid_code"));
    }
    sqlx::query("UPDATE users SET is_verified=true,updated_at=now() WHERE id=$1 AND NOT is_banned")
        .bind(body.user_id)
        .execute(&mut *tx)
        .await?;
    enqueue(
        &mut tx,
        &state.crypto,
        "identity.email_verified",
        body.user_id,
        json!({"user_id":body.user_id}),
        trace(&headers),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"verified":true})))
}
#[derive(Deserialize)]
struct Login {
    email: String,
    password: String,
    device_name: Option<String>,
}
async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Login>,
) -> ApiResult<Response> {
    csrf(&state, &headers)?;
    let email = email(&body.email)?;
    rate(&state, "login-ip", &ip(&headers), 100).await?;
    rate(&state, "login-email", &email, 15).await?;
    let row=sqlx::query("SELECT u.id,u.password_hash,u.is_verified,u.is_banned,COALESCE(m.is_enabled,false) mfa_enabled FROM users u LEFT JOIN mfa_secrets m ON m.user_id=u.id WHERE u.email=$1").bind(&email).fetch_optional(&state.db).await?;
    let hash=row.as_ref().map(|r|r.get::<String,_>("password_hash")).unwrap_or_else(||"$argon2id$v=19$m=19456,t=2,p=1$RHVtbXlTYWx0Rm9yTG9naW4$meLm9WCR3S1PguzSB7zDlJn7Hq0MTD5trOtdKzOEHqA".into());
    let valid = verify_password(&state, body.password, hash.clone()).await?;
    let row = row.ok_or_else(ApiError::unauthorized)?;
    if !valid || row.get::<bool, _>("is_banned") {
        return Err(ApiError::unauthorized());
    }
    if !row.get::<bool, _>("is_verified") {
        return Err(ApiError {
            status: StatusCode::FORBIDDEN,
            code: "email_not_verified",
        });
    }
    let uid: Uuid = row.get("id");
    let mut tx = state.db.begin().await?;
    let current: String = sqlx::query_scalar(
        "SELECT password_hash FROM users WHERE id=$1 AND NOT is_banned AND is_verified FOR UPDATE",
    )
    .bind(uid)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(ApiError::unauthorized)?;
    if !constant_eq(&current, &hash) {
        return Err(ApiError::unauthorized());
    }
    let mfa_enabled: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mfa_secrets WHERE user_id=$1 AND is_enabled)",
    )
    .bind(uid)
    .fetch_one(&mut *tx)
    .await?;
    if mfa_enabled {
        let challenge = random_token();
        sqlx::query("INSERT INTO identity_challenges(id,user_id,kind,token_hash,expires_at,metadata) VALUES($1,$2,'mfa_login',$3,now()+interval '5 minutes',$4)").bind(Uuid::new_v4()).bind(uid).bind(digest(&challenge)).bind(json!({"ip_address":ip(&headers),"user_agent":agent(&headers),"device_name":body.device_name})).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(Json(json!({"status":"mfa_required","challenge_id":challenge})).into_response());
    }
    let (sid, token, csrf) = create_session(
        &state,
        &mut tx,
        uid,
        false,
        &headers,
        body.device_name.as_deref(),
    )
    .await?;
    tx.commit().await?;
    authenticated_response(&state, uid, sid, &token, &csrf).await
}
async fn create_session(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    uid: Uuid,
    mfa: bool,
    headers: &HeaderMap,
    device: Option<&str>,
) -> ApiResult<(Uuid, String, String)> {
    let available: bool = sqlx::query_scalar(
        "SELECT is_verified AND NOT is_banned FROM users WHERE id=$1 FOR UPDATE",
    )
    .bind(uid)
    .fetch_one(&mut **tx)
    .await?;
    if !available {
        return Err(ApiError::unauthorized());
    }
    let sid = Uuid::now_v7();
    let token = random_token();
    let csrf = random_token();
    let device = device
        .unwrap_or("Browser")
        .chars()
        .take(100)
        .collect::<String>();
    let now = Utc::now();
    sqlx::query("INSERT INTO sessions(id,user_id,ip_address,user_agent,device_name,expires_at,cookie_hash,csrf_hash,mfa_verified,mfa_verified_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,CASE WHEN $9 THEN now() ELSE NULL END)").bind(sid).bind(uid).bind(ip(headers)).bind(agent(headers)).bind(&device).bind(now+chrono::Duration::seconds(state.config.session_ttl_seconds)).bind(digest(&token)).bind(digest(&csrf)).bind(mfa).execute(&mut **tx).await?;
    enqueue(tx,&state.crypto,"identity.user_logged_in",uid,json!({"user_id":uid,"session_id":sid,"ip_address":ip(headers),"user_agent":agent(headers),"device_name":device,"logged_in_at":now}),trace(headers)).await?;
    Ok((sid, token, csrf))
}
async fn authenticated_response(
    state: &AppState,
    uid: Uuid,
    sid: Uuid,
    token: &str,
    csrf: &str,
) -> ApiResult<Response> {
    let mut headers = HeaderMap::new();
    headers.insert(
        "cookie",
        HeaderValue::from_str(&format!("sso_session={token}"))
            .map_err(|_| ApiError::dependency())?,
    );
    let actor = authenticate(state, &headers).await?;
    debug_assert_eq!(actor.user_id, uid);
    Ok(response_with_cookies(
        StatusCode::OK,
        json!({"status":"authenticated","user":user_json(&actor),"session_id":sid,"csrf_token":csrf}),
        Some(token),
        csrf,
        state.config.session_ttl_seconds,
    ))
}
fn user_json(actor: &Actor) -> Value {
    json!({"id":actor.user_id,"email":actor.email,"is_verified":actor.is_verified,"mfa_enabled":actor.mfa_enabled,"mfa_verified":actor.mfa_verified,"roles":actor.roles,"permissions":actor.permissions})
}
async fn me(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let actor = authenticate(&state, &headers).await?;
    Ok(Json(
        json!({"user":user_json(&actor),"session_id":actor.session_id,"mfa_verified":actor.mfa_verified,"csrf_token":cookie(&headers,"sso_csrf")}),
    ))
}
async fn revoke_tx(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    uid: Uuid,
    sid: Option<Uuid>,
    reason: &str,
    headers: &HeaderMap,
) -> ApiResult<usize> {
    let ids = crate::application::security::revoke(
        &mut crate::adapters::postgres::security::PostgresSecurityTransaction { transaction: tx },
        uid,
        sid,
        reason,
    )
    .await?;
    for id in &ids {
        enqueue(
            tx,
            &state.crypto,
            "identity.session_revoked",
            uid,
            json!({"user_id":uid,"session_id":id,"reason":reason}),
            trace(headers),
        )
        .await?;
    }
    Ok(ids.len())
}
async fn logout(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    let actor = mutation(&state, &headers).await?;
    let mut tx = state.db.begin().await?;
    lock_authorized_actor(&mut tx, &actor, false, None).await?;
    revoke_tx(
        &state,
        &mut tx,
        actor.user_id,
        Some(actor.session_id),
        "logout",
        &headers,
    )
    .await?;
    tx.commit().await?;
    Ok(response_with_cookies(
        StatusCode::OK,
        json!({"revoked":true}),
        Some(""),
        "",
        0,
    ))
}
async fn sessions(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let actor = authenticate(&state, &headers).await?;
    let rows=sqlx::query("SELECT id,device_name,ip_address,user_agent,created_at,expires_at,last_active_at FROM sessions WHERE user_id=$1 AND is_active AND expires_at>now() ORDER BY (id=$2) DESC,last_active_at DESC,id DESC").bind(actor.user_id).bind(actor.session_id).fetch_all(&state.db).await?;
    Ok(Json(Value::Array(rows.into_iter().map(|r| {
        let ua=r.get::<String,_>("user_agent");let (browser,os)=session_metadata(&ua);
        let device=r.get::<Option<String>,_>("device_name").filter(|s|!s.trim().is_empty()).unwrap_or_else(||"unknown".into());
        let label=if device!="unknown"{device.clone()}else if browser=="unknown"&&os=="unknown"{"unknown".into()}else{format!("{browser} / {os}")};
        json!({"session_id":r.get::<Uuid,_>("id"),"device_name":device,"device_label":label,"browser":browser,"os":os,"ip_address":r.get::<String,_>("ip_address"),"user_agent":ua,"created_at":r.get::<DateTime<Utc>,_>("created_at"),"expires_at":r.get::<DateTime<Utc>,_>("expires_at"),"last_active_at":r.get::<DateTime<Utc>,_>("last_active_at"),"is_current":r.get::<Uuid,_>("id")==actor.session_id})
    }).collect())))
}
async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(sid): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let actor = mutation(&state, &headers).await?;
    let mut tx = state.db.begin().await?;
    lock_authorized_actor(&mut tx, &actor, false, None).await?;
    let owner: Option<Uuid> = sqlx::query_scalar("SELECT user_id FROM sessions WHERE id=$1")
        .bind(sid)
        .fetch_optional(&mut *tx)
        .await?;
    if owner != Some(actor.user_id) {
        return Err(ApiError::forbidden());
    }
    revoke_tx(
        &state,
        &mut tx,
        actor.user_id,
        Some(sid),
        "user_revoked",
        &headers,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"revoked":true})))
}
async fn revoke_all(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    let actor = mutation(&state, &headers).await?;
    let mut tx = state.db.begin().await?;
    lock_authorized_actor(&mut tx, &actor, false, None).await?;
    let count = revoke_tx(
        &state,
        &mut tx,
        actor.user_id,
        None,
        "user_revoked_all",
        &headers,
    )
    .await?;
    tx.commit().await?;
    Ok(response_with_cookies(
        StatusCode::OK,
        json!({"revoked":count}),
        Some(""),
        "",
        0,
    ))
}

pub fn session_metadata(ua: &str) -> (&'static str, &'static str) {
    let browser = if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("Firefox/") {
        "Firefox"
    } else if ua.contains("Chrome/") {
        "Chrome"
    } else if ua.contains("Safari/") {
        "Safari"
    } else {
        "unknown"
    };
    let os = if ua.contains("Android") {
        "Android"
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        "iOS"
    } else if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Mac OS") {
        "macOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "unknown"
    };
    (browser, os)
}
async fn revoke_others(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let actor = mutation(&state, &headers).await?;
    let mut tx = state.db.begin().await?;
    lock_authorized_actor(&mut tx, &actor, false, None).await?;
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM sessions WHERE user_id=$1 AND id<>$2 AND is_active ORDER BY id",
    )
    .bind(actor.user_id)
    .bind(actor.session_id)
    .fetch_all(&mut *tx)
    .await?;
    let mut count = 0;
    for id in ids {
        count += revoke_tx(
            &state,
            &mut tx,
            actor.user_id,
            Some(id),
            "user_revoked_others",
            &headers,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(json!({"revoked":count})))
}
