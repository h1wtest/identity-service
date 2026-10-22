use std::sync::Arc;
use axum::{
    extract::{Path, State},
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
use crate::application::register::{RegisterCommand, RegisterUseCase};
use crate::application::sessions::SessionsUseCase;
use crate::domain::errors::AuthError;
use crate::domain::ports::CryptoService;

#[derive(Clone)]
pub struct AppState {
    pub register_use_case: Arc<RegisterUseCase>,
    pub login_use_case: Arc<LoginUseCase>,
    pub mfa_use_case: Arc<MfaUseCase>,
    pub sessions_use_case: Arc<SessionsUseCase>,
    pub crypto: Arc<dyn CryptoService>,
}

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/auth/register", post(register_handler))
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
            AuthError::UserAlreadyExists(msg) => (StatusCode::CONFLICT, msg.clone()),
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid email or password".to_string()),
            AuthError::AccountBanned(reason) => (StatusCode::FORBIDDEN, format!("Account banned: {}", reason)),
            AuthError::InvalidMfaCode => (StatusCode::BAD_REQUEST, "Invalid MFA verification code".to_string()),
            AuthError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AuthError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid or expired token".to_string()),
            AuthError::UserNotFound => (StatusCode::NOT_FOUND, "User not found".to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.0.to_string()),
        };

        let body = Json(json!({
            "error": err_msg,
        }));

        (status, body).into_response()
    }
}
