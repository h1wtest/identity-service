use crate::{security::Crypto, ApiError, ApiResult};
use chrono::{DateTime, Utc};
use platform_contracts::eventsv2::{validate_payload, Envelope};
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// New writes use v2 only. Already-stored v1 envelopes drain without rewriting IDs.
pub async fn enqueue(
    tx: &mut Transaction<'_, Postgres>,
    crypto: &Crypto,
    event_type: &str,
    aggregate_id: Uuid,
    payload: Value,
    traceparent: Option<&str>,
) -> ApiResult<Uuid> {
    enqueue_with_deadline(
        tx,
        crypto,
        event_type,
        aggregate_id,
        payload,
        traceparent,
        None,
    )
    .await
}

pub async fn enqueue_registration(
    tx: &mut Transaction<'_, Postgres>,
    crypto: &Crypto,
    aggregate_id: Uuid,
    payload: Value,
    traceparent: Option<&str>,
    deadline: Option<DateTime<Utc>>,
) -> ApiResult<Uuid> {
    enqueue_with_deadline(
        tx,
        crypto,
        "identity.user_registered",
        aggregate_id,
        payload,
        traceparent,
        deadline,
    )
    .await
}

async fn enqueue_with_deadline(
    tx: &mut Transaction<'_, Postgres>,
    crypto: &Crypto,
    event_type: &str,
    aggregate_id: Uuid,
    payload: Value,
    traceparent: Option<&str>,
    deadline: Option<DateTime<Utc>>,
) -> ApiResult<Uuid> {
    validate_payload(event_type, &payload).map_err(|_| ApiError::bad("invalid_event_payload"))?;
    let aggregate_key = aggregate_id.to_string();
    if payload.get("user_id").and_then(Value::as_str) != Some(aggregate_key.as_str()) {
        return Err(ApiError::bad("event_aggregate_mismatch"));
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(&aggregate_key)
        .execute(&mut **tx)
        .await?;
    let sensitive = event_type.starts_with("notification.");
    let version: i64 = if sensitive {
        1
    } else {
        sqlx::query_scalar("INSERT INTO identity_aggregate_versions(aggregate_id,version) VALUES($1,1) ON CONFLICT(aggregate_id) DO UPDATE SET version=identity_aggregate_versions.version+1 RETURNING version").bind(aggregate_id).fetch_one(&mut **tx).await?
    };
    let occurred_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    if deadline.is_some_and(|limit| occurred_at >= limit) {
        return Err(ApiError::bad("referral_claim_expired"));
    }
    if event_type == "identity.user_registered" {
        sqlx::query("UPDATE users SET created_at=$2 WHERE id=$1")
            .bind(aggregate_id)
            .bind(occurred_at)
            .execute(&mut **tx)
            .await?;
    }
    let id = Uuid::now_v7();
    let encrypted_payload = if sensitive {
        Some(
            crypto
                .encrypt(
                    &id.to_string(),
                    &serde_json::to_vec(&payload).map_err(|_| ApiError::dependency())?,
                )
                .map_err(|_| ApiError::dependency())?,
        )
    } else {
        None
    };
    let event_aggregate = if sensitive { id } else { aggregate_id };
    let e = Envelope {
        schema_version: 2,
        event_id: id,
        event_type: event_type.into(),
        producer: "identity".into(),
        aggregate_type: if sensitive {
            "delivery_command"
        } else {
            "user"
        }
        .into(),
        aggregate_id: event_aggregate,
        aggregate_version: version,
        occurred_at,
        correlation_id: None,
        causation_id: None,
        traceparent: traceparent.map(str::to_owned),
        payload: if sensitive { None } else { Some(payload) },
        encrypted_payload,
    };
    e.validate()
        .map_err(|_| ApiError::bad("invalid_event_envelope"))?;
    let topic = e.topic().map_err(|_| ApiError::bad("invalid_event_type"))?;
    sqlx::query("INSERT INTO outbox_events(id,event_type,aggregate_id,topic,payload) VALUES($1,$2,$3,$4,$5)").bind(id).bind(event_type).bind(event_aggregate.to_string()).bind(topic).bind(serde_json::to_value(&e).map_err(|_|ApiError::dependency())?).execute(&mut **tx).await?;
    Ok(id)
}
