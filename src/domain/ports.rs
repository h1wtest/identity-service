use async_trait::async_trait;
use uuid::Uuid;

use crate::domain::entities::{
    AccessTokenClaims, OutboxEvent, PreAuthTokenClaims, RedisSessionData, Session, TokenPair, User,
};
use crate::domain::errors::AuthError;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create_user(&self, user: &User) -> Result<(), AuthError>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, AuthError>;
    async fn set_banned(&self, id: Uuid, is_banned: bool, reason: Option<&str>) -> Result<(), AuthError>;
    async fn set_verified(&self, id: Uuid, is_verified: bool) -> Result<(), AuthError>;
}

#[async_trait]
pub trait RbacRepository: Send + Sync {
    async fn get_user_roles(&self, user_id: Uuid) -> Result<Vec<String>, AuthError>;
    async fn get_user_permissions(&self, user_id: Uuid) -> Result<Vec<String>, AuthError>;
    async fn assign_role(&self, user_id: Uuid, role_slug: &str) -> Result<(), AuthError>;
    async fn check_permission(&self, user_id: Uuid, permission: &str) -> Result<bool, AuthError>;
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn save_session(&self, session: &RedisSessionData, ttl_seconds: usize) -> Result<(), AuthError>;
    async fn get_session(&self, session_id: &str) -> Result<Option<RedisSessionData>, AuthError>;
    async fn delete_session(&self, session_id: &str) -> Result<(), AuthError>;
    async fn delete_user_sessions(&self, user_id: &str) -> Result<u32, AuthError>;
    async fn get_user_session_ids(&self, user_id: &str) -> Result<Vec<String>, AuthError>;
    async fn save_verification_code(&self, user_id: Uuid, code: &str, ttl_seconds: usize) -> Result<(), AuthError>;
    async fn get_verification_code(&self, user_id: Uuid) -> Result<Option<String>, AuthError>;
    async fn delete_verification_code(&self, user_id: Uuid) -> Result<(), AuthError>;
}

#[async_trait]
pub trait SessionMetadataRepository: Send + Sync {
    async fn record_session(&self, session: &Session) -> Result<(), AuthError>;
    async fn list_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, AuthError>;
    async fn revoke_session(&self, session_id: Uuid, reason: &str) -> Result<(), AuthError>;
    async fn revoke_all_sessions(&self, user_id: Uuid, reason: &str) -> Result<u32, AuthError>;
}

#[async_trait]
pub trait OutboxRepository: Send + Sync {
    async fn save_event(&self, event: &OutboxEvent) -> Result<(), AuthError>;
    async fn fetch_unprocessed(&self, limit: i64) -> Result<Vec<OutboxEvent>, AuthError>;
    async fn mark_processed(&self, id: Uuid) -> Result<(), AuthError>;
    async fn record_failure(&self, id: Uuid, err: &str) -> Result<(), AuthError>;
    async fn lock_next_batch(&self, limit: i64) -> Result<Vec<OutboxEvent>, AuthError>;
    async fn mark_batch_processed(&self, ids: &[Uuid]) -> Result<(), AuthError>;
}
#[async_trait]
pub trait MfaRepository: Send + Sync {
    async fn save_secret(&self, user_id: Uuid, secret: &str) -> Result<(), AuthError>;
    async fn get_secret(&self, user_id: Uuid) -> Result<Option<String>, AuthError>;
    async fn enable_mfa(&self, user_id: Uuid) -> Result<(), AuthError>;
    async fn disable_mfa(&self, user_id: Uuid) -> Result<(), AuthError>;
    async fn is_mfa_enabled(&self, user_id: Uuid) -> Result<bool, AuthError>;
    async fn save_recovery_codes(&self, user_id: Uuid, hashes: &[String]) -> Result<(), AuthError>;
    async fn consume_recovery_code(&self, user_id: Uuid, hash: &str) -> Result<bool, AuthError>;
}

pub trait CryptoService: Send + Sync {
    fn hash_password(&self, password: &str) -> Result<String, AuthError>;
    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, AuthError>;
    fn generate_token_pair(
        &self,
        user_id: &str,
        session_id: &str,
        roles: &[String],
        permissions: &[String],
    ) -> Result<TokenPair, AuthError>;
    fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims, AuthError>;
    fn generate_pre_auth_token(&self, user_id: &str, session_id: &str) -> Result<String, AuthError>;
    fn verify_pre_auth_token(&self, token: &str) -> Result<PreAuthTokenClaims, AuthError>;
    fn generate_id_token(
        &self,
        issuer: &str,
        client_id: &str,
        user_id: &str,
        email: &str,
        roles: &[String],
        permissions: &[String],
    ) -> Result<String, AuthError>;
}

#[async_trait]
pub trait OAuthClientRepository: Send + Sync {
    async fn find_client(&self, client_id: &str) -> Result<Option<crate::domain::entities::OAuthClient>, AuthError>;
}

#[async_trait]
pub trait OAuthCodeStore: Send + Sync {
    async fn save_code(&self, auth_code: &crate::domain::entities::OAuthAuthorizationCode, ttl_seconds: usize) -> Result<(), AuthError>;
    async fn consume_code(&self, code: &str) -> Result<Option<crate::domain::entities::OAuthAuthorizationCode>, AuthError>;
}
