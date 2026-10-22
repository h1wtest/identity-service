use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::domain::entities::OutboxEvent;
use crate::domain::errors::AuthError;
use crate::domain::ports::OutboxRepository;

#[derive(Clone)]
pub struct PostgresOutboxRepository {
    pool: PgPool,
}

impl PostgresOutboxRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OutboxRepository for PostgresOutboxRepository {
    async fn save_event(&self, event: &OutboxEvent) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            INSERT INTO outbox_events (
                id, event_type, aggregate_id, payload, headers,
                is_processed, retry_count, last_error, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(event.id)
        .bind(&event.event_type)
        .bind(&event.aggregate_id)
        .bind(&event.payload)
        .bind(&event.headers)
        .bind(event.is_processed)
        .bind(event.retry_count)
        .bind(&event.last_error)
        .bind(event.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn fetch_unprocessed(&self, limit: i64) -> Result<Vec<OutboxEvent>, AuthError> {
        let rows = sqlx::query(
            r#"
            SELECT id, event_type, aggregate_id, payload, headers,
                   is_processed, retry_count, last_error, created_at
            FROM outbox_events
            WHERE is_processed = FALSE
            ORDER BY created_at ASC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let events = rows
            .into_iter()
            .map(|r| OutboxEvent {
                id: r.get("id"),
                event_type: r.get("event_type"),
                aggregate_id: r.get("aggregate_id"),
                payload: r.get("payload"),
                headers: r.get("headers"),
                is_processed: r.get("is_processed"),
                retry_count: r.get("retry_count"),
                last_error: r.get("last_error"),
                created_at: r.get("created_at"),
            })
            .collect();

        Ok(events)
    }

    async fn mark_processed(&self, id: Uuid) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE outbox_events
            SET is_processed = TRUE, processed_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn record_failure(&self, id: Uuid, err: &str) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE outbox_events
            SET retry_count = retry_count + 1, last_error = $1
            WHERE id = $2
            "#,
        )
        .bind(err)
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
