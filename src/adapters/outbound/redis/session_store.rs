use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;

use crate::domain::entities::RedisSessionData;
use crate::domain::errors::AuthError;
use crate::domain::ports::SessionStore;

#[derive(Clone)]
pub struct RedisSessionStore {
    manager: ConnectionManager,
}

impl RedisSessionStore {
    pub async fn new(redis_url: &str) -> Result<Self, AuthError> {
        let client = redis::Client::open(redis_url)
            .map_err(|e| AuthError::CacheError(format!("Invalid Redis URL: {}", e)))?;
        let manager = ConnectionManager::new(client)
            .await
            .map_err(|e| AuthError::CacheError(format!("Failed to connect to Redis: {}", e)))?;

        Ok(Self { manager })
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn save_session(&self, session: &RedisSessionData, ttl_seconds: usize) -> Result<(), AuthError> {
        let mut conn = self.manager.clone();
        let session_key = format!("session:{}", session.session_id);
        let user_sessions_key = format!("user_sessions:{}", session.user_id);
        let payload = serde_json::to_string(session)
            .map_err(|e| AuthError::Internal(format!("Failed to serialize session: {}", e)))?;

        conn.set_ex::<_, _, ()>(&session_key, payload, ttl_seconds as u64)
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;

        conn.sadd::<_, _, ()>(&user_sessions_key, &session.session_id)
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;

        conn.expire::<_, ()>(&user_sessions_key, ttl_seconds as i64)
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;

        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<RedisSessionData>, AuthError> {
        let mut conn = self.manager.clone();
        let session_key = format!("session:{}", session_id);

        let data: Option<String> = conn
            .get(&session_key)
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;

        match data {
            Some(raw) => {
                let session = serde_json::from_str(&raw)
                    .map_err(|e| AuthError::Internal(format!("Failed to deserialize session: {}", e)))?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), AuthError> {
        let mut conn = self.manager.clone();
        let session_key = format!("session:{}", session_id);

        if let Ok(Some(session)) = self.get_session(session_id).await {
            let user_sessions_key = format!("user_sessions:{}", session.user_id);
            let _: Result<(), _> = conn.srem(&user_sessions_key, session_id).await;
        }

        conn.del::<_, ()>(&session_key)
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;

        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &str) -> Result<u32, AuthError> {
        let mut conn = self.manager.clone();
        let user_sessions_key = format!("user_sessions:{}", user_id);

        let session_ids: Vec<String> = conn
            .smembers(&user_sessions_key)
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;

        let mut count = 0;
        for sid in &session_ids {
            let key = format!("session:{}", sid);
            let _: Result<(), _> = conn.del(key).await;
            count += 1;
        }

        let _: Result<(), _> = conn.del(user_sessions_key).await;

        Ok(count)
    }

    async fn get_user_session_ids(&self, user_id: &str) -> Result<Vec<String>, AuthError> {
        let mut conn = self.manager.clone();
        let user_sessions_key = format!("user_sessions:{}", user_id);

        let ids: Vec<String> = conn
            .smembers(&user_sessions_key)
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;

        Ok(ids)
    }
}
