use std::sync::Arc;
use chrono::Utc;
use serde::Serialize;
use uuid::Uuid;

use crate::domain::entities::{OutboxEvent, Session};
use crate::domain::errors::AuthError;
use crate::domain::ports::{OutboxRepository, SessionMetadataRepository, SessionStore};

#[derive(Debug, Serialize)]
pub struct SessionResponseItem {
    pub session_id: Uuid,
    pub ip_address: String,
    pub user_agent: String,
    pub device_name: Option<String>,
    pub location: Option<String>,
    pub is_current: bool,
    pub created_at: String,
    pub last_active_at: String,
}

pub struct SessionsUseCase {
    session_store: Arc<dyn SessionStore>,
    session_metadata_repo: Arc<dyn SessionMetadataRepository>,
    outbox_repo: Arc<dyn OutboxRepository>,
}

impl SessionsUseCase {
    pub fn new(
        session_store: Arc<dyn SessionStore>,
        session_metadata_repo: Arc<dyn SessionMetadataRepository>,
        outbox_repo: Arc<dyn OutboxRepository>,
    ) -> Self {
        Self {
            session_store,
            session_metadata_repo,
            outbox_repo,
        }
    }

    pub async fn list_sessions(
        &self,
        user_id: Uuid,
        current_session_id: Option<Uuid>,
    ) -> Result<Vec<SessionResponseItem>, AuthError> {
        let db_sessions = self.session_metadata_repo.list_user_sessions(user_id).await?;

        let items = db_sessions
            .into_iter()
            .map(|s: Session| {
                let is_current = current_session_id.map(|cid| cid == s.id).unwrap_or(false);
                SessionResponseItem {
                    session_id: s.id,
                    ip_address: s.ip_address,
                    user_agent: s.user_agent,
                    device_name: s.device_name,
                    location: s.location,
                    is_current,
                    created_at: s.created_at.to_rfc3339(),
                    last_active_at: s.last_active_at.to_rfc3339(),
                }
            })
            .collect();

        Ok(items)
    }

    pub async fn revoke_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        reason: &str,
    ) -> Result<(), AuthError> {
        let session_id_str = session_id.to_string();

        // 1. Invalidate in Redis
        self.session_store.delete_session(&session_id_str).await?;

        // 2. Mark inactive in Postgres
        self.session_metadata_repo.revoke_session(session_id, reason).await?;

        // 3. Emit SessionRevokedEvent to Outbox
        let now = Utc::now();
        let event_payload = serde_json::json!({
            "event_id": Uuid::now_v7().to_string(),
            "event_type": "auth.session_revoked",
            "timestamp": now.to_rfc3339(),
            "producer": "identity-service",
            "session_revoked": {
                "user_id": user_id.to_string(),
                "session_id": session_id_str,
                "reason": reason,
                "revoked_at": now.to_rfc3339(),
            }
        });

        let outbox_event = OutboxEvent {
            id: Uuid::now_v7(),
            event_type: "auth.session_revoked".to_string(),
            aggregate_id: user_id.to_string(),
            payload: event_payload,
            headers: serde_json::json!({"trace_id": Uuid::now_v7().to_string()}),
            is_processed: false,
            retry_count: 0,
            last_error: None,
            created_at: now,
        };
        self.outbox_repo.save_event(&outbox_event).await?;

        Ok(())
    }

    pub async fn revoke_all_sessions(&self, user_id: Uuid, reason: &str) -> Result<u32, AuthError> {
        let user_id_str = user_id.to_string();

        // 1. Delete all Redis sessions
        let count = self.session_store.delete_user_sessions(&user_id_str).await?;

        // 2. Mark all inactive in Postgres
        self.session_metadata_repo.revoke_all_sessions(user_id, reason).await?;

        // 3. Emit SessionRevokedEvent
        let now = Utc::now();
        let event_payload = serde_json::json!({
            "event_id": Uuid::now_v7().to_string(),
            "event_type": "auth.session_revoked",
            "timestamp": now.to_rfc3339(),
            "producer": "identity-service",
            "session_revoked": {
                "user_id": user_id_str,
                "session_id": "all",
                "reason": reason,
                "revoked_at": now.to_rfc3339(),
            }
        });

        let outbox_event = OutboxEvent {
            id: Uuid::now_v7(),
            event_type: "auth.session_revoked".to_string(),
            aggregate_id: user_id_str,
            payload: event_payload,
            headers: serde_json::json!({"trace_id": Uuid::now_v7().to_string()}),
            is_processed: false,
            retry_count: 0,
            last_error: None,
            created_at: now,
        };
        self.outbox_repo.save_event(&outbox_event).await?;

        Ok(count)
    }
}
