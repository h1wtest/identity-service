use crate::security::PayloadCipher;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub fn key_from_env(name: &str) -> Result<[u8; 32]> {
    STANDARD
        .decode(std::env::var(name).with_context(|| format!("{name} required"))?)
        .map_err(|_| anyhow::anyhow!("{name} must encode 32 bytes"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must encode 32 bytes"))
}
fn rewrap(
    old: &PayloadCipher,
    new: &PayloadCipher,
    aad: &str,
    encrypted: &str,
) -> Result<Option<String>> {
    if new.decrypt(aad, encrypted).is_ok() {
        return Ok(None);
    }
    let plaintext = old.decrypt(aad, encrypted).map_err(|_| {
        anyhow::anyhow!("ciphertext cannot be authenticated with supplied migration keys")
    })?;
    Ok(Some(new.encrypt(aad, &plaintext)?))
}
/// Caller must stop legacy writers before invoking; all retained rows change atomically.
pub async fn run(
    pool: &PgPool,
    legacy_key: [u8; 32],
    mfa_key: [u8; 32],
    delivery_key: [u8; 32],
) -> Result<()> {
    if mfa_key == delivery_key {
        anyhow::bail!("MFA and delivery purpose keys must differ");
    }
    let old = PayloadCipher::new(legacy_key);
    let mfa = PayloadCipher::new(mfa_key);
    let delivery = PayloadCipher::new(delivery_key);
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(742915831)")
        .execute(&mut *tx)
        .await?;
    let exists: bool = sqlx::query_scalar("SELECT to_regclass('mfa_secrets') IS NOT NULL")
        .fetch_one(&mut *tx)
        .await?;
    if exists {
        for row in sqlx::query("SELECT user_id,secret_key FROM mfa_secrets FOR UPDATE")
            .fetch_all(&mut *tx)
            .await?
        {
            let uid: Uuid = row.get("user_id");
            let secret: String = row.get("secret_key");
            let replacement = if let Some(encrypted) = secret.strip_prefix("enc:") {
                rewrap(&old, &mfa, &uid.to_string(), encrypted)?
            } else {
                Some(mfa.encrypt(&uid.to_string(), secret.as_bytes())?)
            };
            if let Some(value) = replacement {
                sqlx::query(
                    "UPDATE mfa_secrets SET secret_key=$2,updated_at=now() WHERE user_id=$1",
                )
                .bind(uid)
                .bind(format!("enc:{value}"))
                .execute(&mut *tx)
                .await?;
            }
        }
    }
    let exists: bool = sqlx::query_scalar("SELECT to_regclass('pending_mfa') IS NOT NULL")
        .fetch_one(&mut *tx)
        .await?;
    if exists {
        for row in sqlx::query("SELECT user_id,encrypted_secret FROM pending_mfa FOR UPDATE")
            .fetch_all(&mut *tx)
            .await?
        {
            let uid: Uuid = row.get("user_id");
            let encrypted: String = row.get("encrypted_secret");
            if let Some(value) = rewrap(&old, &mfa, &uid.to_string(), &encrypted)? {
                sqlx::query("UPDATE pending_mfa SET encrypted_secret=$2 WHERE user_id=$1")
                    .bind(uid)
                    .bind(value)
                    .execute(&mut *tx)
                    .await?;
            }
        }
    }
    let exists: bool = sqlx::query_scalar("SELECT to_regclass('outbox_events') IS NOT NULL")
        .fetch_one(&mut *tx)
        .await?;
    if exists {
        for row in sqlx::query("SELECT id,event_type,payload FROM outbox_events WHERE payload ? 'encrypted_payload' OR event_type LIKE 'notification.%' FOR UPDATE").fetch_all(&mut *tx).await? {
            let id:Uuid=row.get("id");let mut payload:serde_json::Value=row.get("payload");
            let envelope:platform_contracts::Envelope=serde_json::from_value(payload.clone()).map_err(|_|anyhow::anyhow!("unknown or plaintext sensitive outbox schema; migration refused"))?;
            if envelope.event_id!=id || !platform_contracts::sensitive(&envelope.event_type){anyhow::bail!("sensitive outbox envelope metadata mismatch");}
            let encrypted=payload.get("encrypted_payload").and_then(serde_json::Value::as_str).ok_or_else(||anyhow::anyhow!("invalid encrypted outbox payload"))?;
            if let Some(value)=rewrap(&old,&delivery,&id.to_string(),encrypted)?{payload["encrypted_payload"]=serde_json::Value::String(value);sqlx::query("UPDATE outbox_events SET payload=$2 WHERE id=$1").bind(id).bind(payload).execute(&mut *tx).await?;}
        }
    }
    tx.commit().await?;
    Ok(())
}
