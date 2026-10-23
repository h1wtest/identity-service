use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use identity_service::{
    auth,
    config::Config,
    create_router,
    security::{digest, Claims},
    AppState,
};
use serde_json::{json, Value};
use sqlx::Row;
use tower::ServiceExt;
use uuid::Uuid;

async fn state() -> AppState {
    let mut cfg = Config::from_env().expect("real signing/TLS/encryption environment required");
    cfg.database_url = std::env::var("TEST_DATABASE_URL")
        .expect("disposable PostgreSQL TEST_DATABASE_URL required");
    let state = AppState::connect(cfg).await.unwrap();
    identity_service::migrate(&state.db).await.unwrap();
    state
}
async fn user(state: &AppState) -> (Uuid, String, String, String) {
    let id = Uuid::new_v4();
    let password = "Correct Horse Battery Staple!42".to_string();
    let hash = auth::hash_password(state, password.clone()).await.unwrap();
    let email = format!("{id}@test.invalid");
    sqlx::query("INSERT INTO users(id,email,password_hash,is_verified) VALUES($1,$2,$3,true)")
        .bind(id)
        .bind(&email)
        .bind(hash)
        .execute(&state.db)
        .await
        .unwrap();
    let token = identity_service::security::random_token();
    let csrf = identity_service::security::random_token();
    sqlx::query("INSERT INTO sessions(id,user_id,ip_address,user_agent,is_active,expires_at,cookie_hash,csrf_hash) VALUES($1,$2,'127.0.0.1','regression',true,now()+interval '1 day',$3,$4)")
        .bind(Uuid::new_v4()).bind(id).bind(digest(&token)).bind(digest(&csrf)).execute(&state.db).await.unwrap();
    (id, email, token, csrf)
}
async fn request(
    state: &AppState,
    method: &str,
    path: &str,
    cookie: &str,
    csrf: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("origin", &state.config.public_origin)
        .header("cookie", format!("sso_session={cookie}; sso_csrf={csrf}"))
        .header("x-csrf-token", csrf)
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap();
    let response = create_router(state.clone()).oneshot(req).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

#[tokio::test]
#[ignore = "requires disposable real PostgreSQL plus signing and distinct MFA/DELIVERY encryption keys"]
async fn foreign_session_revoke_is_atomic_and_leaves_victim_live() {
    let s = state().await;
    let (_, _, a, csrf) = user(&s).await;
    let (victim, _, b, _) = user(&s).await;
    let sid: Uuid = sqlx::query_scalar("SELECT id FROM sessions WHERE user_id=$1")
        .bind(victim)
        .fetch_one(&s.db)
        .await
        .unwrap();
    let (status, _) = request(
        &s,
        "DELETE",
        &format!("/api/v1/auth/sessions/{sid}"),
        &a,
        &csrf,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("cookie", format!("sso_session={b}").parse().unwrap());
    assert_eq!(
        auth::authenticate(&s, &headers).await.unwrap().user_id,
        victim
    );
}

#[tokio::test]
#[ignore = "requires disposable real PostgreSQL plus signing and distinct MFA/DELIVERY encryption keys"]
async fn revoked_signed_access_token_is_rejected_immediately() {
    let s = state().await;
    let (uid, _, cookie, _) = user(&s).await;
    let sid: Uuid = sqlx::query_scalar("SELECT id FROM sessions WHERE user_id=$1")
        .bind(uid)
        .fetch_one(&s.db)
        .await
        .unwrap();
    let now = chrono::Utc::now().timestamp() as usize;
    let jwt = s
        .crypto
        .sign(&Claims {
            iss: s.config.issuer.clone(),
            aud: s.config.public_origin.clone(),
            sub: uid,
            sid,
            exp: now + 300,
            iat: now,
            token_use: "access".into(),
            scope: "platform:api".into(),
            nonce: None,
            email: None,
            email_verified: None,
        })
        .unwrap();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("authorization", format!("Bearer {jwt}").parse().unwrap());
    assert!(auth::authenticate(&s, &headers).await.is_ok());
    sqlx::query("UPDATE sessions SET is_active=false WHERE cookie_hash=$1")
        .bind(digest(&cookie))
        .execute(&s.db)
        .await
        .unwrap();
    assert!(auth::authenticate(&s, &headers).await.is_err());
}

#[tokio::test]
#[ignore = "requires disposable real PostgreSQL plus signing and distinct MFA/DELIVERY encryption keys"]
async fn mfa_setup_requires_reauth_and_preserves_active_secret() {
    let s = state().await;
    let (uid, _, cookie, csrf) = user(&s).await;
    let sealed = format!(
        "enc:{}",
        s.crypto
            .encrypt_mfa(&uid.to_string(), b"JBSWY3DPEHPK3PXP")
            .unwrap()
    );
    sqlx::query("INSERT INTO mfa_secrets(user_id,secret_key,is_enabled) VALUES($1,$2,true)")
        .bind(uid)
        .bind(&sealed)
        .execute(&s.db)
        .await
        .unwrap();
    let (status, _) = request(
        &s,
        "POST",
        "/api/v1/auth/mfa/setup",
        &cookie,
        &csrf,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let row = sqlx::query("SELECT secret_key,is_enabled FROM mfa_secrets WHERE user_id=$1")
        .bind(uid)
        .fetch_one(&s.db)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("secret_key"), sealed);
    assert!(row.get::<bool, _>("is_enabled"));
}

#[tokio::test]
#[ignore = "requires disposable real PostgreSQL plus signing and distinct MFA/DELIVERY encryption keys"]
async fn mutation_rejects_missing_csrf_and_foreign_origin() {
    let s = state().await;
    let (_, _, cookie, csrf) = user(&s).await;
    let response = create_router(s.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header("origin", "https://evil.invalid")
                .header("cookie", format!("sso_session={cookie}; sso_csrf={csrf}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[ignore = "requires disposable real PostgreSQL plus signing and distinct MFA/DELIVERY encryption keys"]
async fn bootstrap_admin_without_mfa_has_no_admin_permission() {
    let s = state().await;
    let (uid, _, cookie, _) = user(&s).await;
    sqlx::query(
        "INSERT INTO user_roles(user_id,role_id) SELECT $1,id FROM roles WHERE slug='admin'",
    )
    .bind(uid)
    .execute(&s.db)
    .await
    .unwrap();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("cookie", format!("sso_session={cookie}").parse().unwrap());
    let actor = auth::authenticate(&s, &headers).await.unwrap();
    assert!(auth::require_permission(&actor, "users:write").is_err());
}

#[test]
fn encrypted_sensitive_payload_binds_event_id_and_detects_tampering() {
    use identity_service::security::PayloadCipher;
    let cipher = PayloadCipher::new([7u8; 32]);
    let encrypted = cipher
        .encrypt("event-one", br#"{"token":"sensitive"}"#)
        .unwrap();
    assert_eq!(
        cipher.decrypt("event-one", &encrypted).unwrap(),
        br#"{"token":"sensitive"}"#
    );
    assert!(cipher.decrypt("event-two", &encrypted).is_err());
}

#[tokio::test]
#[ignore = "requires disposable real PostgreSQL plus signing and distinct MFA/DELIVERY encryption keys"]
async fn explicit_invalid_bearer_never_falls_back_to_live_cookie() {
    let s = state().await;
    let (_, _, cookie, _) = user(&s).await;
    for value in ["Bearer invalid.jwt.value", "Basic invalid", "Bearer "] {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("cookie", format!("sso_session={cookie}").parse().unwrap());
        headers.insert("authorization", value.parse().unwrap());
        assert!(auth::authenticate(&s, &headers).await.is_err());
    }
}

#[tokio::test]
#[ignore = "requires disposable real PostgreSQL plus signing and distinct MFA/DELIVERY encryption keys"]
async fn ambient_cookie_requires_csrf_even_with_valid_bearer() {
    let s = state().await;
    let (uid, _, cookie, _) = user(&s).await;
    let sid: Uuid = sqlx::query_scalar("SELECT id FROM sessions WHERE user_id=$1")
        .bind(uid)
        .fetch_one(&s.db)
        .await
        .unwrap();
    let now = chrono::Utc::now().timestamp() as usize;
    let jwt = s
        .crypto
        .sign(&Claims {
            iss: s.config.issuer.clone(),
            aud: s.config.public_origin.clone(),
            sub: uid,
            sid,
            exp: now + 300,
            iat: now,
            token_use: "access".into(),
            scope: "platform:api".into(),
            nonce: None,
            email: None,
            email_verified: None,
        })
        .unwrap();
    let response = create_router(s.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header("authorization", format!("Bearer {jwt}"))
                .header("cookie", format!("sso_session={cookie}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = create_router(s.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header("authorization", format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore = "requires disposable real PostgreSQL plus signing and distinct MFA/DELIVERY encryption keys"]
async fn oidc_client_access_never_grants_platform_management_even_with_cookie() {
    let s = state().await;
    let (uid, _, cookie, csrf) = user(&s).await;
    let sid: Uuid = sqlx::query_scalar("SELECT id FROM sessions WHERE user_id=$1")
        .bind(uid)
        .fetch_one(&s.db)
        .await
        .unwrap();
    let now = chrono::Utc::now().timestamp() as usize;
    let token = s
        .crypto
        .sign(&Claims {
            iss: s.config.issuer.clone(),
            aud: "web-demo".into(),
            sub: uid,
            sid,
            exp: now + 300,
            iat: now,
            token_use: "access".into(),
            scope: "openid email profile".into(),
            nonce: None,
            email: None,
            email_verified: None,
        })
        .unwrap();
    let response = create_router(s.clone())
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/auth/sessions")
                .header("authorization", format!("Bearer {token}"))
                .header("cookie", format!("sso_session={cookie}; sso_csrf={csrf}"))
                .header("x-csrf-token", csrf)
                .header("origin", &s.config.public_origin)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let live: bool = sqlx::query_scalar("SELECT is_active FROM sessions WHERE id=$1")
        .bind(sid)
        .fetch_one(&s.db)
        .await
        .unwrap();
    assert!(live);
}
