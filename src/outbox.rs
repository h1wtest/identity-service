use crate::{adapters::kafka::KafkaPublisher, domain::events::Publisher, AppState};
use platform_contracts::Envelope;
use rand::Rng;
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::time::Duration;
use uuid::Uuid;

const LEASE_SECONDS: i64 = 60;
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct ClaimedEvent {
    pub id: Uuid,
    pub lease_token: Uuid,
    pub aggregate_id: Uuid,
    pub topic: String,
    pub payload: Value,
    pub attempts: i32,
}

/// One unacknowledged head per aggregate; durable leases survive process termination.
/// SKIP LOCKED permits independent aggregates to advance without waiting on another worker.
pub async fn claim(pool: &PgPool) -> Result<Option<ClaimedEvent>, sqlx::Error> {
    let lease_token = Uuid::new_v4();
    let row = sqlx::query(
        "WITH candidate AS (
            SELECT e.id FROM outbox_events e
            WHERE NOT e.is_processed AND e.next_attempt_at <= now()
              AND (e.lease_until IS NULL OR e.lease_until <= now())
              AND NOT EXISTS (SELECT 1 FROM outbox_events predecessor
                  WHERE predecessor.aggregate_id=e.aggregate_id AND NOT predecessor.is_processed
                    AND predecessor.sequence < e.sequence)
            ORDER BY e.sequence FOR UPDATE OF e SKIP LOCKED LIMIT 1
         ) UPDATE outbox_events e SET lease_token=$1,
             lease_until=now()+($2::bigint*interval '1 second'),retry_count=LEAST(e.retry_count::bigint+1,2147483647)::int
           FROM candidate WHERE e.id=candidate.id
         RETURNING e.id,e.lease_token,e.aggregate_id,e.topic,e.payload,e.retry_count")
        .bind(lease_token).bind(LEASE_SECONDS).fetch_optional(pool).await?;
    row.map(|row| {
        Ok(ClaimedEvent {
            id: row.try_get("id")?,
            lease_token: row.try_get("lease_token")?,
            aggregate_id: Uuid::parse_str(row.try_get::<&str, _>("aggregate_id")?)
                .map_err(|err| sqlx::Error::Decode(Box::new(err)))?,
            topic: row.try_get("topic")?,
            payload: row.try_get("payload")?,
            attempts: row.try_get("retry_count")?,
        })
    })
    .transpose()
}

/// Fencing prevents an expired owner from acknowledging a newer worker's claim.
pub async fn acknowledge(pool: &PgPool, event: &ClaimedEvent) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("UPDATE outbox_events SET is_processed=true,processed_at=now(),lease_token=NULL,lease_until=NULL,last_error=NULL WHERE id=$1 AND lease_token=$2 AND lease_until>now() AND NOT is_processed")
        .bind(event.id).bind(event.lease_token).execute(pool).await?.rows_affected() == 1)
}

pub async fn retry(pool: &PgPool, event: &ClaimedEvent) -> Result<bool, sqlx::Error> {
    // Equal jitter: [half cap, cap], doubling to a five-minute ceiling. Retry never
    // drops an authoritative event; a permanent failure holds only its aggregate.
    let cap = (2_i64.saturating_pow(event.attempts.clamp(1, 9) as u32)).min(300);
    let seconds = rand::thread_rng().gen_range((cap / 2).max(1)..=cap);
    Ok(sqlx::query("UPDATE outbox_events SET lease_token=NULL,lease_until=NULL,next_attempt_at=now()+($3::bigint*interval '1 second'),last_error='broker_publish_failed' WHERE id=$1 AND lease_token=$2 AND lease_until>now() AND NOT is_processed")
        .bind(event.id).bind(event.lease_token).bind(seconds).execute(pool).await?.rows_affected() == 1)
}

/// Identity readiness is deliberately independent of Kafka: SQL durably accepts work.
pub async fn run(state: AppState) {
    let mut client = None;
    let mut cleanup = tokio::time::Instant::now();
    loop {
        if client.is_none() {
            match tokio::time::timeout(PUBLISH_TIMEOUT, KafkaPublisher::connect(&state.config))
                .await
            {
                Ok(Ok(connected)) => client = Some(connected),
                _ => {
                    tracing::warn!("outbox broker unavailable");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            }
        }
        if cleanup.elapsed() >= Duration::from_secs(3600) {
            // Published sensitive bodies have a maximum additional SQL retention of 24h.
            if sqlx::query("DELETE FROM outbox_events WHERE topic IS NOT NULL AND is_processed AND processed_at < now()-interval '24 hours'").execute(&state.db).await.is_err() { tracing::warn!("outbox retention cleanup failed"); }
            cleanup = tokio::time::Instant::now();
        }
        let event = match claim(&state.db).await {
            Ok(Some(event)) => event,
            Ok(None) => {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
            Err(_) => {
                tracing::warn!("outbox claim unavailable");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let span = tracing::info_span!("outbox.publish", event_id=%event.id, aggregate_id=%event.aggregate_id, traceparent=event.payload.get("traceparent").and_then(serde_json::Value::as_str).unwrap_or(""));
        if let Some(parent) = event.payload.get("traceparent").and_then(Value::as_str) {
            crate::telemetry::attach_traceparent(&span, parent);
        }
        let outcome = {
            use tracing::Instrument;
            // Total network budget is below the lease. Dropping the timed-out future
            // cancels local retries; ambiguous broker acknowledgement remains at-least-once.
            tokio::time::timeout(PUBLISH_TIMEOUT, async {
                let publisher = client.as_ref().expect("connected publisher");
                if event.payload.get("schema_version").and_then(Value::as_i64) == Some(2) {
                    let envelope: platform_contracts::eventsv2::Envelope =
                        serde_json::from_value(event.payload.clone())?;
                    if envelope.event_id != event.id || envelope.aggregate_id != event.aggregate_id
                    {
                        anyhow::bail!("outbox identity mismatch")
                    }
                    publisher.publish_v2(&event.topic, &envelope).await
                } else {
                    let envelope: Envelope = serde_json::from_value(event.payload.clone())?;
                    if envelope.event_id != event.id || envelope.aggregate_id != event.aggregate_id
                    {
                        anyhow::bail!("outbox identity mismatch")
                    }
                    publisher.publish(&event.topic, &envelope).await
                }
            })
            .instrument(span)
            .await
        };
        match outcome {
            Ok(Ok(())) => {
                if !matches!(acknowledge(&state.db, &event).await, Ok(true)) {
                    tracing::warn!(event_id=%event.id,"outbox acknowledgement lost; event may repeat");
                }
            }
            _ => {
                if retry(&state.db, &event).await.is_err() {
                    tracing::warn!(event_id=%event.id,"outbox retry persistence failed; lease will recover");
                }
                tracing::warn!(event_id=%event.id,"outbox publication failed");
                client = None;
            }
        }
    }
}
