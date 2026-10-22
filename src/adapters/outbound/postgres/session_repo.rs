use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::domain::entities::Session;
use crate::domain::errors::AuthError;
use crate::domain::ports::SessionMetadataRepository;

#[derive(Clone)]
pub struct PostgresSessionMetadataRepository {
    pool: PgPool,
}

impl PostgresSessionMetadataRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionMetadataRepository for PostgresSessionMetadataRepository {
    async fn record_session(&self, session: &Session) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            INSERT INTO sessions (
                id, user_id, ip_address, user_agent, device_name, location,
                is_active, revoked_reason, created_at, last_active_at, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (id) DO UPDATE SET
                last_active_at = EXCLUDED.last_active_at,
                is_active = EXCLUDED.is_active
            "#,
        )
        .bind(session.id)
        .bind(session.user_id)
        .bind(&session.ip_address)
        .bind(&session.user_agent)
        .bind(&session.device_name)
        .bind(&session.location)
        .bind(session.is_active)
        .bind(&session.revoked_reason)
        .bind(session.created_at)
        .bind(session.last_active_at)
        .bind(session.expires_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, AuthError> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, ip_address, user_agent, device_name, location,
                   is_active, revoked_reason, created_at, last_active_at, expires_at
            FROM sessions
            WHERE user_id = $1 AND is_active = TRUE AND expires_at > NOW()
            ORDER BY last_active_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let sessions = rows
            .into_iter()
            .map(|r| Session {
                id: r.get("id"),
                user_id: r.get("user_id"),
                ip_address: r.get("ip_address"),
                user_agent: r.get("user_agent"),
                device_name: r.get("device_name"),
                location: r.get("location"),
                is_active: r.get("is_active"),
                revoked_reason: r.get("revoked_reason"),
                created_at: r.get("created_at"),
                last_active_at: r.get("last_active_at"),
                expires_at: r.get("expires_at"),
            })
            .collect();

        Ok(sessions)
    }

    async fn revoke_session(&self, session_id: Uuid, reason: &str) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE sessions
            SET is_active = FALSE, revoked_reason = $1
            WHERE id = $2
            "#,
        )
        .bind(reason)
        .bind(session_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn revoke_all_sessions(&self, user_id: Uuid, reason: &str) -> Result<u32, AuthError> {
        let res = sqlx::query(
            r#"
            UPDATE sessions
            SET is_active = FALSE, revoked_reason = $1
            WHERE user_id = $2 AND is_active = TRUE
            "#,
        )
        .bind(reason)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(res.rows_affected() as u32)
    }
}
