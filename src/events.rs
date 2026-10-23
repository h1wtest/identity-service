use crate::{security::Crypto, ApiError, ApiResult};
use chrono::Utc;
use platform_contracts::{sensitive, topic, validate_payload, Envelope};
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Enqueue inside the authoritative mutation transaction. No secret plaintext reaches SQL.
pub async fn enqueue(
    tx: &mut Transaction<'_, Postgres>,
    crypto: &Crypto,
    event_type: &str,
    aggregate_id: Uuid,
    payload: Value,
    traceparent: Option<&str>,
) -> ApiResult<Uuid> {
    validate_payload(event_type, &payload).map_err(|_| ApiError::bad("invalid_event_payload"))?;
    let aggregate_key = aggregate_id.to_string();
    if payload.get("user_id").and_then(Value::as_str) != Some(aggregate_key.as_str()) {
        return Err(ApiError::bad("event_aggregate_mismatch"));
    }
    let event_id = Uuid::new_v4();
    let topic = topic(event_type).map_err(|_| ApiError::bad("invalid_event_type"))?;
    let encrypted_payload = if sensitive(event_type) {
        let bytes = serde_json::to_vec(&payload).map_err(|_| ApiError::dependency())?;
        Some(
            crypto
                .encrypt(&event_id.to_string(), &bytes)
                .map_err(|_| ApiError::dependency())?,
        )
    } else {
        None
    };
    let envelope = Envelope {
        schema_version: 1,
        event_id,
        event_type: event_type.to_owned(),
        aggregate_id,
        occurred_at: Utc::now(),
        traceparent: traceparent.map(str::to_owned),
        payload: if sensitive(event_type) {
            None
        } else {
            Some(payload)
        },
        encrypted_payload,
    };
    let stored =
        serde_json::to_value(envelope).map_err(|_| ApiError::bad("invalid_event_envelope"))?;
    // Serialize enqueue order per aggregate before sequence allocation. This prevents a later
    // transaction from committing/publishing ahead of an earlier uncommitted aggregate event.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(&aggregate_key)
        .execute(&mut **tx)
        .await?;
    sqlx::query("INSERT INTO outbox_events(id,event_type,aggregate_id,topic,payload) VALUES($1,$2,$3,$4,$5)")
        .bind(event_id).bind(event_type).bind(&aggregate_key).bind(topic).bind(stored)
        .execute(&mut **tx).await?;
    Ok(event_id)
}
