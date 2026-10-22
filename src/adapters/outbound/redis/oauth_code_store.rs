use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;

use crate::domain::entities::OAuthAuthorizationCode;
use crate::domain::errors::AuthError;
use crate::domain::ports::OAuthCodeStore;

#[derive(Clone)]
pub struct RedisOAuthCodeStore {
    manager: ConnectionManager,
}

impl RedisOAuthCodeStore {
    pub fn new(manager: ConnectionManager) -> Self {
        Self { manager }
    }
}

#[async_trait]
impl OAuthCodeStore for RedisOAuthCodeStore {
    async fn save_code(
        &self,
        auth_code: &OAuthAuthorizationCode,
        ttl_seconds: usize,
    ) -> Result<(), AuthError> {
        let mut conn = self.manager.clone();
        let key = format!("oauth_code:{}", auth_code.code);
        let payload = serde_json::to_string(auth_code)
            .map_err(|e| AuthError::Internal(format!("Failed to serialize oauth code: {}", e)))?;

        conn.set_ex::<_, _, ()>(&key, payload, ttl_seconds as u64)
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;

        Ok(())
    }

    async fn consume_code(
        &self,
        code: &str,
    ) -> Result<Option<OAuthAuthorizationCode>, AuthError> {
        let mut conn = self.manager.clone();
        let key = format!("oauth_code:{}", code);

        // Fetch data
        let data: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;

        if let Some(raw) = data {
            // Delete immediately (one-time use!)
            let _: Result<(), _> = conn.del(&key).await;

            let auth_code = serde_json::from_str(&raw)
                .map_err(|e| AuthError::Internal(format!("Failed to deserialize oauth code: {}", e)))?;
            Ok(Some(auth_code))
        } else {
            Ok(None)
        }
    }
}
