use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub is_verified: bool,
    pub is_banned: bool,
    pub ban_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub ip_address: String,
    pub user_agent: String,
    pub device_name: Option<String>,
    pub location: Option<String>,
    pub is_active: bool,
    pub revoked_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Permission {
    pub id: Uuid,
    pub slug: String,
    pub module: String,
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboxEvent {
    pub id: Uuid,
    pub event_type: String,
    pub aggregate_id: String,
    pub payload: serde_json::Value,
    pub headers: serde_json::Value,
    pub is_processed: bool,
    pub retry_count: i32,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub token_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,                  // user_id
    pub sid: String,                  // session_id
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreAuthTokenClaims {
    pub sub: String,                  // user_id
    pub session_id: String,
    pub scope: String,                // "mfa_pending"
    pub exp: i64,
    pub iat: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedisSessionData {
    pub session_id: String,
    pub user_id: String,
    pub refresh_token_hash: String,
    pub refresh_token_family: String,
    pub ip_address: String,
    pub user_agent: String,
    pub device_name: Option<String>,
    pub location: Option<String>,
    pub created_at: i64,
    pub last_active_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub is_public: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OAuthAuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcIdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub auth_time: i64,
    pub email: String,
    pub email_verified: bool,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: String,
}
