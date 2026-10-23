use super::*;
#[derive(Deserialize)]
pub(super) struct Forgot {
    email: String,
}
pub(super) async fn forgot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Forgot>,
) -> ApiResult<Json<Value>> {
    csrf(&state, &headers)?;
    rate(&state, "forgot-ip", &ip(&headers), 30).await?;
    let email = email(&body.email)?;
    rate(&state, "forgot-email", &email, 5).await?;
    let mut tx = state.db.begin().await?;
    let uid: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM users WHERE email=$1 AND NOT is_banned AND is_verified FOR UPDATE",
    )
    .bind(&email)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(uid) = uid {
        let token = random_token();
        let expires = Utc::now() + chrono::Duration::minutes(15);
        sqlx::query("UPDATE identity_challenges SET consumed_at=now() WHERE user_id=$1 AND kind='password_reset' AND consumed_at IS NULL").bind(uid).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO identity_challenges(id,user_id,kind,token_hash,expires_at) VALUES($1,$2,'password_reset',$3,$4)").bind(Uuid::new_v4()).bind(uid).bind(digest(&token)).bind(expires).execute(&mut *tx).await?;
        enqueue(
            &mut tx,
            &state.crypto,
            "notification.password_reset",
            uid,
            json!({"user_id":uid,"email":email,"token":token,"expires_at":expires}),
            trace(&headers),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(
        json!({"accepted":true,"message":"If the account is eligible, recovery instructions will be emailed"}),
    ))
}
#[derive(Deserialize)]
pub(super) struct Reset {
    token: String,
    password: String,
}
pub(super) async fn reset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Reset>,
) -> ApiResult<Json<Value>> {
    csrf(&state, &headers)?;
    rate(&state, "reset-ip", &ip(&headers), 30).await?;
    rate(&state, "reset-token", &body.token, 5).await?;
    let hash = hash_password(&state, body.password).await?;
    let mut tx = state.db.begin().await?;
    let uid: Uuid = sqlx::query_scalar(
        "SELECT user_id FROM identity_challenges WHERE kind='password_reset' AND token_hash=$1",
    )
    .bind(digest(&body.token))
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::bad("invalid_reset_token"))?;
    let allowed: Option<bool> =
        sqlx::query_scalar("SELECT NOT is_banned FROM users WHERE id=$1 FOR UPDATE")
            .bind(uid)
            .fetch_optional(&mut *tx)
            .await?;
    if allowed != Some(true) {
        return Err(ApiError::bad("invalid_reset_token"));
    }
    let challenge:Option<Uuid>=sqlx::query_scalar("SELECT id FROM identity_challenges WHERE user_id=$1 AND kind='password_reset' AND token_hash=$2 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE").bind(uid).bind(digest(&body.token)).fetch_optional(&mut *tx).await?;
    if challenge.is_none() {
        return Err(ApiError::bad("invalid_reset_token"));
    }
    sqlx::query("UPDATE users SET password_hash=$2,updated_at=now() WHERE id=$1")
        .bind(uid)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE identity_challenges SET consumed_at=now() WHERE user_id=$1 AND consumed_at IS NULL",
    )
    .bind(uid)
    .execute(&mut *tx)
    .await?;
    revoke_tx(&state, &mut tx, uid, None, "password_reset", &headers).await?;
    enqueue(
        &mut tx,
        &state.crypto,
        "identity.password_changed",
        uid,
        json!({"user_id":uid}),
        trace(&headers),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"password_changed":true})))
}
#[derive(Deserialize)]
pub(super) struct Change {
    current_password: String,
    password: String,
}
pub(super) async fn change(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Change>,
) -> ApiResult<Response> {
    let actor = mutation(&state, &headers).await?;
    mfa::require_fresh(&state, &actor).await?;
    rate(&state, "password-change", &actor.user_id.to_string(), 5).await?;
    let old: String =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id=$1 AND NOT is_banned")
            .bind(actor.user_id)
            .fetch_one(&state.db)
            .await?;
    if !verify_password(&state, body.current_password, old.clone()).await? {
        return Err(ApiError::unauthorized());
    }
    let hash = hash_password(&state, body.password).await?;
    let mut tx = state.db.begin().await?;
    let revoked = crate::application::security::change_password(
        &mut crate::adapters::postgres::security::PostgresSecurityTransaction {
            transaction: &mut tx,
        },
        actor.user_id,
        actor.session_id,
        &old,
        &hash,
    )
    .await?;
    sqlx::query(
        "UPDATE identity_challenges SET consumed_at=now() WHERE user_id=$1 AND consumed_at IS NULL",
    )
    .bind(actor.user_id)
    .execute(&mut *tx)
    .await?;
    for session_id in revoked {
        enqueue(
            &mut tx,
            &state.crypto,
            "identity.session_revoked",
            actor.user_id,
            json!({"user_id":actor.user_id,"session_id":session_id,"reason":"password_changed"}),
            trace(&headers),
        )
        .await?;
    }
    enqueue(
        &mut tx,
        &state.crypto,
        "identity.password_changed",
        actor.user_id,
        json!({"user_id":actor.user_id}),
        trace(&headers),
    )
    .await?;
    tx.commit().await?;
    Ok(response_with_cookies(
        StatusCode::OK,
        json!({"password_changed":true}),
        Some(""),
        "",
        0,
    ))
}
