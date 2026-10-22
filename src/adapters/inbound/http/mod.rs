use std::sync::Arc;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::application::login::{LoginCommand, LoginUseCase};
use crate::application::mfa::{MfaUseCase, VerifyMfaLoginCommand};
use crate::application::register::{RegisterCommand, RegisterUseCase, VerifyEmailCommand, VerifyEmailUseCase};
use crate::application::sessions::SessionsUseCase;
use crate::application::oauth::OAuthUseCase;
use crate::domain::errors::AuthError;
use crate::domain::ports::CryptoService;

#[derive(Clone)]
pub struct AppState {
    pub register_use_case: Arc<RegisterUseCase>,
    pub verify_email_use_case: Arc<VerifyEmailUseCase>,
    pub login_use_case: Arc<LoginUseCase>,
    pub mfa_use_case: Arc<MfaUseCase>,
    pub sessions_use_case: Arc<SessionsUseCase>,
    pub oauth_use_case: Arc<OAuthUseCase>,
    pub crypto: Arc<dyn CryptoService>,
    pub issuer: String,
}

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(health_check))
        .route("/.well-known/openid-configuration", get(openid_configuration_handler))
        .route("/.well-known/jwks.json", get(jwks_handler))
        .route("/oauth/authorize", get(oauth_authorize_handler))
        .route("/oauth/token", post(oauth_token_handler))
        .route("/oauth/userinfo", get(oauth_userinfo_handler))
        .route("/api/v1/auth/register", post(register_handler))
        .route("/api/v1/auth/verify-email", post(verify_email_handler))
        .route("/api/v1/auth/login", post(login_handler))
        .route("/api/v1/auth/mfa/verify-login", post(verify_mfa_login_handler))
        .route("/api/v1/auth/mfa/setup", post(setup_mfa_handler))
        .route("/api/v1/auth/mfa/enable", post(enable_mfa_handler))
        .route("/api/v1/auth/sessions", get(list_sessions_handler))
        .route("/api/v1/auth/sessions/{id}", delete(revoke_session_handler))
        .route("/api/v1/auth/sessions", delete(revoke_all_sessions_handler))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status": "ok", "service": "identity-service"})))
}

#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    password: String,
}

async fn register_handler(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    let cmd = RegisterCommand {
        email: payload.email,
        password: payload.password,
    };

    let result = state.register_use_case.execute(cmd).await?;
    Ok((StatusCode::CREATED, Json(result)))
}

#[derive(Deserialize)]
struct VerifyEmailRequest {
    user_id: Uuid,
    code: String,
}

async fn verify_email_handler(
    State(state): State<AppState>,
    Json(payload): Json<VerifyEmailRequest>,
) -> Result<impl IntoResponse, AppError> {
    let cmd = VerifyEmailCommand {
        user_id: payload.user_id,
        code: payload.code,
    };

    let result = state.verify_email_use_case.execute(cmd).await?;
    Ok((StatusCode::OK, Json(result)))
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
    device_name: Option<String>,
    location: Option<String>,
}

async fn login_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1")
        .to_string();

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown Browser")
        .to_string();

    let cmd = LoginCommand {
        email: payload.email,
        password: payload.password,
        ip_address,
        user_agent,
        device_name: payload.device_name,
        location: payload.location,
    };

    let result = state.login_use_case.execute(cmd).await?;
    Ok((StatusCode::OK, Json(result)))
}

#[derive(Deserialize)]
struct VerifyMfaLoginRequest {
    pre_auth_token: String,
    code: String,
    device_name: Option<String>,
    location: Option<String>,
}

async fn verify_mfa_login_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<VerifyMfaLoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1")
        .to_string();

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown Browser")
        .to_string();

    let cmd = VerifyMfaLoginCommand {
        pre_auth_token: payload.pre_auth_token,
        code: payload.code,
        ip_address,
        user_agent,
        device_name: payload.device_name,
        location: payload.location,
    };

    let result = state.mfa_use_case.verify_login_mfa(cmd).await?;
    Ok((StatusCode::OK, Json(result)))
}

// Helper to extract caller's user_id and session_id from Bearer header
fn extract_auth(headers: &HeaderMap, crypto: &dyn CryptoService) -> Result<(Uuid, Uuid), AppError> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError(AuthError::Unauthorized("Missing Authorization header".to_string())))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError(AuthError::Unauthorized("Invalid Authorization header format".to_string())));
    }

    let token = &auth_header[7..];
    let claims = crypto.verify_access_token(token)?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError(AuthError::InvalidToken))?;
    let session_id = Uuid::parse_str(&claims.sid)
        .map_err(|_| AppError(AuthError::InvalidToken))?;

    Ok((user_id, session_id))
}

async fn setup_mfa_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let (user_id, _) = extract_auth(&headers, state.crypto.as_ref())?;
    let result = state.mfa_use_case.setup_mfa(user_id).await?;
    Ok((StatusCode::OK, Json(result)))
}

#[derive(Deserialize)]
struct EnableMfaRequest {
    code: String,
}

async fn enable_mfa_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<EnableMfaRequest>,
) -> Result<impl IntoResponse, AppError> {
    let (user_id, _) = extract_auth(&headers, state.crypto.as_ref())?;
    state.mfa_use_case.enable_mfa(user_id, &payload.code).await?;
    Ok((StatusCode::OK, Json(json!({"message": "MFA enabled successfully"}))))
}

async fn list_sessions_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let (user_id, session_id) = extract_auth(&headers, state.crypto.as_ref())?;
    let sessions = state.sessions_use_case.list_sessions(user_id, Some(session_id)).await?;
    Ok((StatusCode::OK, Json(sessions)))
}

async fn revoke_session_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(target_session_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let (user_id, _) = extract_auth(&headers, state.crypto.as_ref())?;
    state
        .sessions_use_case
        .revoke_session(user_id, target_session_id, "user_revoked_via_lk")
        .await?;
    Ok((StatusCode::OK, Json(json!({"message": "Session revoked successfully"}))))
}

async fn revoke_all_sessions_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let (user_id, _) = extract_auth(&headers, state.crypto.as_ref())?;
    let count = state
        .sessions_use_case
        .revoke_all_sessions(user_id, "user_revoked_all_via_lk")
        .await?;
    Ok((StatusCode::OK, Json(json!({"message": "All sessions revoked", "count": count}))))
}

async fn openid_configuration_handler(State(state): State<AppState>) -> impl IntoResponse {
    let issuer = &state.issuer;
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/oauth/authorize", issuer),
        "token_endpoint": format!("{}/oauth/token", issuer),
        "userinfo_endpoint": format!("{}/oauth/userinfo", issuer),
        "jwks_uri": format!("{}/.well-known/jwks.json", issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code", "refresh_token"]
    }))
}

async fn jwks_handler() -> impl IntoResponse {
    Json(json!({
        "keys": [
            {
                "kty": "oct",
                "alg": "HS256",
                "use": "sig",
                "kid": "sso-hmac-key-1"
            }
        ]
    }))
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    scope: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    state: Option<String>,
}

async fn oauth_authorize_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthorizeQuery>,
) -> Result<impl IntoResponse, AppError> {
    let (user_id, _) = extract_auth(&headers, state.crypto.as_ref())?;
    let scope = query.scope.unwrap_or_else(|| "openid profile email".to_string());

    let redirect_url = state.oauth_use_case.authorize(
        user_id,
        &query.client_id,
        &query.redirect_uri,
        &query.response_type,
        &scope,
        &query.code_challenge,
        &query.code_challenge_method,
        query.state.as_deref(),
    ).await?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "redirect_url": redirect_url,
            "status": "authorized"
        }))
    ))
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    client_id: String,
    code: String,
    redirect_uri: String,
    code_verifier: String,
}

async fn oauth_token_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<TokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    if payload.grant_type != "authorization_code" {
        return Err(AppError(AuthError::Internal(
            "Unsupported grant_type. Only 'authorization_code' is supported".to_string(),
        )));
    }

    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1");

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("OAuth Client");

    let response = state.oauth_use_case.exchange_token(
        &payload.client_id,
        &payload.redirect_uri,
        &payload.code,
        &payload.code_verifier,
        ip_address,
        user_agent,
    ).await?;

    Ok((StatusCode::OK, Json(response)))
}

async fn oauth_userinfo_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let (user_id, _) = extract_auth(&headers, state.crypto.as_ref())?;
    let info = state.oauth_use_case.get_userinfo(user_id).await?;
    Ok((StatusCode::OK, Json(info)))
}

// Error adapter for Axum
pub struct AppError(pub AuthError);

impl From<AuthError> for AppError {
    fn from(err: AuthError) -> Self {
        AppError(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, err_msg) = match &self.0 {
            AuthError::UserAlreadyExists(msg) => (StatusCode::CONFLICT, json!({ "error": msg })),
            AuthError::EmailNotVerified { user_id, email } => (
                StatusCode::FORBIDDEN,
                json!({
                    "error": "Email address is not verified",
                    "code": "email_not_verified",
                    "user_id": user_id,
                    "email": email
                }),
            ),
            AuthError::InvalidVerificationCode => (StatusCode::BAD_REQUEST, json!({ "error": "Invalid or expired email verification code" })),
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, json!({ "error": "Invalid email or password" })),
            AuthError::AccountBanned(reason) => (StatusCode::FORBIDDEN, json!({ "error": format!("Account banned: {}", reason) })),
            AuthError::InvalidMfaCode => (StatusCode::BAD_REQUEST, json!({ "error": "Invalid MFA verification code" })),
            AuthError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, json!({ "error": msg })),
            AuthError::Forbidden(msg) => (StatusCode::FORBIDDEN, json!({ "error": msg })),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, json!({ "error": "Invalid or expired token" })),
            AuthError::UserNotFound => (StatusCode::NOT_FOUND, json!({ "error": "User not found" })),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": self.0.to_string() })),
        };

        (status, Json(err_msg)).into_response()
    }
}
