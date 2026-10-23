use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use identity_service::{
    auth,
    config::Config,
    create_router,
    security::{digest, random_token},
    AppState,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;
async fn fixture() -> (AppState, Uuid, String, String, String) {
    let mut config = Config::from_env().unwrap();
    config.database_url = std::env::var("TEST_DATABASE_URL").unwrap();
    let state = AppState::connect(config).await.unwrap();
    identity_service::migrate(&state.db).await.unwrap();
    let uid = Uuid::new_v4();
    let email = format!("{uid}@test.invalid");
    let hash = auth::hash_password(&state, "Good Correct Password!123".into())
        .await
        .unwrap();
    sqlx::query("INSERT INTO users(id,email,password_hash,is_verified) VALUES($1,$2,$3,true)")
        .bind(uid)
        .bind(&email)
        .bind(hash)
        .execute(&state.db)
        .await
        .unwrap();
    let cookie = random_token();
    let csrf = random_token();
    sqlx::query("INSERT INTO sessions(id,user_id,ip_address,user_agent,cookie_hash,csrf_hash,expires_at) VALUES($1,$2,'127.0.0.1','real-test',$3,$4,now()+interval '1 day')").bind(Uuid::new_v4()).bind(uid).bind(digest(&cookie)).bind(digest(&csrf)).execute(&state.db).await.unwrap();
    (state, uid, email, cookie, csrf)
}
async fn post(
    state: &AppState,
    path: &str,
    cookie: &str,
    csrf: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("origin", &state.config.public_origin)
                .header("cookie", format!("sso_session={cookie}; sso_csrf={csrf}"))
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
#[tokio::test]
#[ignore = "requires real disposable TEST_DATABASE_URL plus signing/encryption/TLS environment"]
async fn recovery_factor_challenge_and_setup_are_single_use_and_preserve_active_factor() {
    let (s, uid, email, cookie, csrf) = fixture().await;
    let sealed = format!(
        "enc:{}",
        s.crypto
            .encrypt_mfa(&uid.to_string(), b"JBSWY3DPEHPK3PXP")
            .unwrap()
    );
    sqlx::query("INSERT INTO mfa_secrets(user_id,secret_key,is_enabled) VALUES($1,$2,true)")
        .bind(uid)
        .bind(sealed)
        .execute(&s.db)
        .await
        .unwrap();
    let recovery = "ONE-TIME-RECOVERY";
    sqlx::query("INSERT INTO recovery_codes(id,user_id,code_hash) VALUES($1,$2,$3)")
        .bind(Uuid::new_v4())
        .bind(uid)
        .bind(digest(recovery))
        .execute(&s.db)
        .await
        .unwrap();
    let (status, body) = post(
        &s,
        "/api/v1/auth/login",
        &cookie,
        &csrf,
        json!({"email":email,"password":"Good Correct Password!123"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let challenge = body["challenge_id"].as_str().unwrap();
    let (status, _) = post(
        &s,
        "/api/v1/auth/mfa/verify-login",
        &cookie,
        &csrf,
        json!({"challenge_id":challenge,"code":recovery}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = post(
        &s,
        "/api/v1/auth/mfa/verify-login",
        &cookie,
        &csrf,
        json!({"challenge_id":challenge,"code":recovery}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = post(
        &s,
        "/api/v1/auth/login",
        &cookie,
        &csrf,
        json!({"email":email,"password":"Good Correct Password!123"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = post(
        &s,
        "/api/v1/auth/mfa/verify-login",
        &cookie,
        &csrf,
        json!({"challenge_id":body["challenge_id"],"code":recovery}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post(&s, "/api/v1/auth/mfa/setup", &cookie, &csrf, json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let enabled: bool = sqlx::query_scalar("SELECT is_enabled FROM mfa_secrets WHERE user_id=$1")
        .bind(uid)
        .fetch_one(&s.db)
        .await
        .unwrap();
    assert!(enabled);
}
#[tokio::test]
#[ignore = "requires real disposable TEST_DATABASE_URL plus signing/encryption/TLS environment"]
async fn reset_token_is_single_use_and_revokes_existing_session_atomically() {
    let (s, uid, _, cookie, csrf) = fixture().await;
    let token = random_token();
    sqlx::query("INSERT INTO identity_challenges(id,user_id,kind,token_hash,expires_at) VALUES($1,$2,'password_reset',$3,now()+interval '1 minute')").bind(Uuid::new_v4()).bind(uid).bind(digest(&token)).execute(&s.db).await.unwrap();
    let (status, _) = post(
        &s,
        "/api/v1/auth/password/reset",
        &cookie,
        &csrf,
        json!({"token":token,"password":"New Correct Password!456"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("cookie", format!("sso_session={cookie}").parse().unwrap());
    assert!(auth::authenticate(&s, &headers).await.is_err());
    let (status, _) = post(
        &s,
        "/api/v1/auth/password/reset",
        &cookie,
        &csrf,
        json!({"token":token,"password":"Another Correct Password!789"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id=$1")
        .bind(uid)
        .fetch_one(&s.db)
        .await
        .unwrap();
    assert!(
        auth::verify_password(&s, "New Correct Password!456".into(), hash)
            .await
            .unwrap()
    );
}
