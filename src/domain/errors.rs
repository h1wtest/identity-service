use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("User with email '{0}' already exists")]
    UserAlreadyExists(String),

    #[error("User not found")]
    UserNotFound,

    #[error("Invalid email or password")]
    InvalidCredentials,

    #[error("Account is banned: {0}")]
    AccountBanned(String),

    #[error("MFA verification is required")]
    MfaRequired { pre_auth_token: String },

    #[error("Invalid MFA code")]
    InvalidMfaCode,

    #[error("MFA is already enabled")]
    MfaAlreadyEnabled,

    #[error("MFA is not configured")]
    MfaNotConfigured,

    #[error("Invalid or expired session")]
    InvalidSession,

    #[error("Token reuse detected: session compromised")]
    TokenReuseDetected,

    #[error("Invalid or expired token")]
    InvalidToken,

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: missing permission '{0}'")]
    Forbidden(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Redis cache error: {0}")]
    CacheError(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<sqlx::Error> for AuthError {
    fn from(err: sqlx::Error) -> Self {
        AuthError::DatabaseError(err.to_string())
    }
}

impl From<redis::RedisError> for AuthError {
    fn from(err: redis::RedisError) -> Self {
        AuthError::CacheError(err.to_string())
    }
}
