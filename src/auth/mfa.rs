use super::*;
use totp_rs::{Algorithm, Secret, TOTP};
fn totp(secret: &str, email: &str) -> ApiResult<TOTP> {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret.to_owned())
            .to_bytes()
            .map_err(|_| ApiError::dependency())?,
        Some("Remediation SSO".into()),
        email.to_owned(),
    )
    .map_err(|_| ApiError::dependency())
}
fn step(secret: &str, email: &str, code: &str) -> ApiResult<Option<i64>> {
    if code.len() != 6 || !code.bytes().all(|v| v.is_ascii_digit()) {
        return Ok(None);
    }
    let totp = totp(secret, email)?;
    let now = Utc::now().timestamp() as u64;
    for time in [now.saturating_sub(30), now, now + 30] {
        if constant_eq(&totp.generate(time), code) {
            return Ok(Some((time / 30) as i64));
        }
    }
    Ok(None)
}
fn active_secret(state: &AppState, uid: Uuid, secret: &str) -> ApiResult<String> {
    let ciphertext = secret
        .strip_prefix("enc:")
        .ok_or_else(ApiError::dependency)?;
    String::from_utf8(
        state
            .crypto
            .decrypt_mfa(&uid.to_string(), ciphertext)
            .map_err(|_| ApiError::dependency())?,
    )
    .map_err(|_| ApiError::dependency())
}
async fn consume_factor(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    uid: Uuid,
    email: &str,
    code: &str,
) -> ApiResult<()> {
    let row=sqlx::query("SELECT secret_key,last_used_step FROM mfa_secrets WHERE user_id=$1 AND is_enabled FOR UPDATE").bind(uid).fetch_optional(&mut **tx).await?.ok_or_else(ApiError::forbidden)?;
    let secret = active_secret(state, uid, &row.get::<String, _>("secret_key"))?;
    if let Some(step) = step(&secret, email, code)? {
        if step <= row.get::<i64, _>("last_used_step") {
            return Err(ApiError::bad("mfa_code_replayed"));
        }
        sqlx::query("UPDATE mfa_secrets SET last_used_step=$2 WHERE user_id=$1")
            .bind(uid)
            .bind(step)
            .execute(&mut **tx)
            .await?;
        return Ok(());
    }
    let count=sqlx::query("UPDATE recovery_codes SET is_used=true,used_at=now() WHERE user_id=$1 AND code_hash=$2 AND NOT is_used").bind(uid).bind(digest(&code.trim().to_uppercase())).execute(&mut **tx).await?;
    if count.rows_affected() != 1 {
        return Err(ApiError::bad("invalid_mfa_code"));
    }
    Ok(())
}
async fn fresh(state: &AppState, actor: &Actor) -> ApiResult<()> {
    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE id=$1 AND is_active AND reauthenticated_at>now()-interval '5 minutes')").bind(actor.session_id).fetch_one(&state.db).await?;
    if !valid {
        return Err(ApiError::forbidden());
    }
    Ok(())
}
#[derive(Deserialize)]
pub(super) struct Reauth {
    password: String,
    code: Option<String>,
}
pub(super) async fn reauth(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Reauth>,
) -> ApiResult<Json<Value>> {
    let actor = mutation(&state, &headers).await?;
    rate(&state, "reauth", &actor.user_id.to_string(), 10).await?;
    let hash: String =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id=$1 AND NOT is_banned")
            .bind(actor.user_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(ApiError::unauthorized)?;
    if !verify_password(&state, body.password, hash.clone()).await? {
        return Err(ApiError::unauthorized());
    }
    let mut tx = state.db.begin().await?;
    let current: String = sqlx::query_scalar(
        "SELECT password_hash FROM users WHERE id=$1 AND NOT is_banned FOR UPDATE",
    )
    .bind(actor.user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(ApiError::unauthorized)?;
    if !constant_eq(&current, &hash) {
        return Err(ApiError::unauthorized());
    }
    let enabled: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mfa_secrets WHERE user_id=$1 AND is_enabled)",
    )
    .bind(actor.user_id)
    .fetch_one(&mut *tx)
    .await?;
    if enabled {
        consume_factor(
            &state,
            &mut tx,
            actor.user_id,
            &actor.email,
            body.code.as_deref().ok_or_else(ApiError::forbidden)?,
        )
        .await?;
    }
    let changed=sqlx::query("UPDATE sessions SET reauthenticated_at=now(),mfa_verified=CASE WHEN $2 THEN true ELSE mfa_verified END,mfa_verified_at=CASE WHEN $2 THEN now() ELSE mfa_verified_at END WHERE id=$1 AND is_active AND expires_at>now()").bind(actor.session_id).bind(enabled).execute(&mut *tx).await?;
    if changed.rows_affected() != 1 {
        return Err(ApiError::unauthorized());
    }
    tx.commit().await?;
    Ok(Json(json!({"reauthenticated":true})))
}
pub(super) async fn setup(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let actor = mutation(&state, &headers).await?;
    fresh(&state, &actor).await?;
    rate(&state, "mfa-setup", &actor.user_id.to_string(), 5).await?;
    let secret = Secret::generate_secret().to_encoded().to_string();
    let recovery_codes: Vec<String> = (0..10)
        .map(|_| random_token()[..16].to_uppercase())
        .collect();
    let hashes: Vec<String> = recovery_codes.iter().map(|v| digest(v)).collect();
    let encrypted = state
        .crypto
        .encrypt_mfa(&actor.user_id.to_string(), secret.as_bytes())
        .map_err(|_| ApiError::dependency())?;
    let mut tx = state.db.begin().await?;
    lock_actor(&mut tx, &actor).await?;
    sqlx::query("INSERT INTO pending_mfa(user_id,session_id,encrypted_secret,recovery_hashes,expires_at) VALUES($1,$2,$3,$4,now()+interval '10 minutes') ON CONFLICT(user_id) DO UPDATE SET session_id=excluded.session_id,encrypted_secret=excluded.encrypted_secret,recovery_hashes=excluded.recovery_hashes,expires_at=excluded.expires_at").bind(actor.user_id).bind(actor.session_id).bind(encrypted).bind(hashes).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"secret":secret,"otpauth_uri":totp(&secret,&actor.email)?.get_url(),"recovery_codes":recovery_codes}),
    ))
}
#[derive(Deserialize)]
pub(super) struct Code {
    code: String,
}
async fn lock_actor(tx: &mut Transaction<'_, Postgres>, actor: &Actor) -> ApiResult<()> {
    lock_authorized_actor(tx, actor, true, None).await
}
pub(super) async fn enable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Code>,
) -> ApiResult<Json<Value>> {
    let actor = mutation(&state, &headers).await?;
    fresh(&state, &actor).await?;
    rate(&state, "mfa-enable", &actor.user_id.to_string(), 10).await?;
    let mut tx = state.db.begin().await?;
    lock_actor(&mut tx, &actor).await?;
    let row=sqlx::query("SELECT encrypted_secret,recovery_hashes FROM pending_mfa WHERE user_id=$1 AND session_id=$2 AND expires_at>now() FOR UPDATE").bind(actor.user_id).bind(actor.session_id).fetch_optional(&mut *tx).await?.ok_or_else(||ApiError::bad("mfa_setup_required"))?;
    let encrypted: String = row.get("encrypted_secret");
    let secret = String::from_utf8(
        state
            .crypto
            .decrypt_mfa(&actor.user_id.to_string(), &encrypted)
            .map_err(|_| ApiError::dependency())?,
    )
    .map_err(|_| ApiError::dependency())?;
    let step = step(&secret, &actor.email, &body.code)?
        .ok_or_else(|| ApiError::bad("invalid_mfa_code"))?;
    sqlx::query("INSERT INTO mfa_secrets(user_id,secret_key,is_enabled,last_used_step) VALUES($1,$2,true,$3) ON CONFLICT(user_id) DO UPDATE SET secret_key=excluded.secret_key,is_enabled=true,last_used_step=excluded.last_used_step,updated_at=now()").bind(actor.user_id).bind(format!("enc:{encrypted}")).bind(step).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM recovery_codes WHERE user_id=$1")
        .bind(actor.user_id)
        .execute(&mut *tx)
        .await?;
    for hash in row.get::<Vec<String>, _>("recovery_hashes") {
        sqlx::query("INSERT INTO recovery_codes(id,user_id,code_hash) VALUES($1,$2,$3)")
            .bind(Uuid::new_v4())
            .bind(actor.user_id)
            .bind(hash)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("DELETE FROM pending_mfa WHERE user_id=$1")
        .bind(actor.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE sessions SET reauthenticated_at=NULL WHERE id=$1")
        .bind(actor.session_id)
        .execute(&mut *tx)
        .await?;
    revoke_others(&state, &mut tx, &actor, &headers, "mfa_changed").await?;
    enqueue(
        &mut tx,
        &state.crypto,
        "identity.mfa_changed",
        actor.user_id,
        json!({"user_id":actor.user_id,"enabled":true}),
        trace(&headers),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"mfa_enabled":true})))
}
async fn revoke_others(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    headers: &HeaderMap,
    reason: &str,
) -> ApiResult<()> {
    let ids:Vec<Uuid>=sqlx::query_scalar("UPDATE sessions SET is_active=false,revoked_reason=$3 WHERE user_id=$1 AND id<>$2 AND is_active RETURNING id").bind(actor.user_id).bind(actor.session_id).bind(reason).fetch_all(&mut **tx).await?;
    for id in ids {
        enqueue(
            tx,
            &state.crypto,
            "identity.session_revoked",
            actor.user_id,
            json!({"user_id":actor.user_id,"session_id":id,"reason":reason}),
            trace(headers),
        )
        .await?;
    }
    Ok(())
}
pub(super) async fn disable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Code>,
) -> ApiResult<Json<Value>> {
    let actor = mutation(&state, &headers).await?;
    fresh(&state, &actor).await?;
    rate(&state, "mfa-disable", &actor.user_id.to_string(), 10).await?;
    let mut tx = state.db.begin().await?;
    lock_actor(&mut tx, &actor).await?;
    consume_factor(&state, &mut tx, actor.user_id, &actor.email, &body.code).await?;
    sqlx::query("UPDATE mfa_secrets SET is_enabled=false,updated_at=now() WHERE user_id=$1")
        .bind(actor.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM recovery_codes WHERE user_id=$1")
        .bind(actor.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM pending_mfa WHERE user_id=$1")
        .bind(actor.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE sessions SET reauthenticated_at=NULL,mfa_verified=false,mfa_verified_at=NULL WHERE id=$1").bind(actor.session_id).execute(&mut *tx).await?;
    revoke_others(&state, &mut tx, &actor, &headers, "mfa_disabled").await?;
    enqueue(
        &mut tx,
        &state.crypto,
        "identity.mfa_changed",
        actor.user_id,
        json!({"user_id":actor.user_id,"enabled":false}),
        trace(&headers),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"mfa_enabled":false})))
}
#[derive(Deserialize)]
pub(super) struct MfaLogin {
    challenge_id: String,
    code: String,
}
pub(super) async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<MfaLogin>,
) -> ApiResult<Response> {
    csrf(&state, &headers)?;
    rate(&state, "mfa-login", &body.challenge_id, 10).await?;
    let mut tx = state.db.begin().await?;
    let uid: Uuid = sqlx::query_scalar(
        "SELECT user_id FROM identity_challenges WHERE kind='mfa_login' AND token_hash=$1",
    )
    .bind(digest(&body.challenge_id))
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(ApiError::unauthorized)?;
    let email: Option<String> = sqlx::query_scalar(
        "SELECT email FROM users WHERE id=$1 AND NOT is_banned AND is_verified FOR UPDATE",
    )
    .bind(uid)
    .fetch_optional(&mut *tx)
    .await?;
    let email = email.ok_or_else(ApiError::unauthorized)?;
    let row=sqlx::query("SELECT id,metadata FROM identity_challenges WHERE user_id=$1 AND kind='mfa_login' AND token_hash=$2 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE").bind(uid).bind(digest(&body.challenge_id)).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::unauthorized)?;
    consume_factor(&state, &mut tx, uid, &email, &body.code).await?;
    sqlx::query("UPDATE identity_challenges SET consumed_at=now() WHERE id=$1")
        .bind(row.get::<Uuid, _>("id"))
        .execute(&mut *tx)
        .await?;
    let metadata: Value = row.get("metadata");
    let (sid, token, csrf) = create_session(
        &state,
        &mut tx,
        uid,
        true,
        &headers,
        metadata.get("device_name").and_then(Value::as_str),
    )
    .await?;
    tx.commit().await?;
    authenticated_response(&state, uid, sid, &token, &csrf).await
}
pub(super) async fn require_fresh(state: &AppState, actor: &Actor) -> ApiResult<()> {
    fresh(state, actor).await
}
