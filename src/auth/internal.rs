use super::*;
use platform_contracts::http::{
    BanRequest, BanResponse, IntrospectRequest, IntrospectResponse, SearchUsersRequest,
    UserSummary, UsersResponse,
};
fn service(state: &AppState, headers: &HeaderMap, admin: bool) -> ApiResult<()> {
    let token = headers
        .get("x-service-token")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(ApiError::unauthorized)?;
    let allowed = if admin {
        constant_eq(token, &state.config.admin_internal_token)
    } else {
        [
            &state.config.profile_internal_token,
            &state.config.notification_internal_token,
            &state.config.admin_internal_token,
        ]
        .iter()
        .any(|v| constant_eq(token, v))
    };
    if allowed {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}
fn set(headers: &mut HeaderMap, key: &'static str, value: &str) -> ApiResult<()> {
    headers.insert(
        key,
        HeaderValue::from_str(value).map_err(|_| ApiError::bad("invalid_header"))?,
    );
    Ok(())
}
fn credentials(headers: &HeaderMap) -> ApiResult<HeaderMap> {
    let mut output = HeaderMap::new();
    for key in ["cookie", "authorization", "origin", "x-csrf-token"] {
        if let Some(value) = headers.get(key) {
            output.insert(key, value.clone());
        }
    }
    if !output.contains_key("cookie") {
        if let Some(token) = headers.get("x-actor-session").and_then(|v| v.to_str().ok()) {
            set(&mut output, "cookie", &format!("sso_session={token}"))?;
        }
    }
    if !output.contains_key("authorization") {
        if let Some(token) = headers.get("x-actor-token").and_then(|v| v.to_str().ok()) {
            set(&mut output, "authorization", &format!("Bearer {token}"))?;
        }
    }
    Ok(output)
}
pub(super) async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<IntrospectRequest>,
) -> ApiResult<Json<IntrospectResponse>> {
    service(&state, &headers, false)?;
    let mut actor_headers = credentials(&headers)?;
    if let Some(token) = body.access_token.filter(|v| !v.is_empty()) {
        set(
            &mut actor_headers,
            "authorization",
            &format!("Bearer {token}"),
        )?;
    } else if let Some(token) = body.session_cookie.filter(|v| !v.is_empty()) {
        let csrf_cookie = cookie(&actor_headers, "sso_csrf");
        set(
            &mut actor_headers,
            "cookie",
            &format!(
                "sso_session={token}{}",
                csrf_cookie
                    .map(|c| format!("; sso_csrf={c}"))
                    .unwrap_or_default()
            ),
        )?;
    }
    if let Some(token) = body.csrf_token.as_deref() {
        set(&mut actor_headers, "x-csrf-token", token)?;
    }
    if let Some(origin) = body.origin.as_deref() {
        set(&mut actor_headers, "origin", origin)?;
    }
    let method = body.method.as_deref().unwrap_or("GET");
    let actor = if !matches!(method, "GET" | "HEAD" | "OPTIONS") {
        mutation(&state, &actor_headers).await?
    } else {
        authenticate(&state, &actor_headers).await?
    };
    if body.require_mfa.unwrap_or(false) && (!actor.mfa_verified || !actor.mfa_enabled) {
        return Err(ApiError::forbidden());
    }
    if let Some(permission) = body.permission.as_deref().filter(|v| !v.is_empty()) {
        if !actor.permissions.iter().any(|p| p == permission) {
            return Err(ApiError::forbidden());
        }
        if matches!(
            permission,
            "users:read" | "users:write" | "audit:read" | "deliveries:read" | "deliveries:replay"
        ) {
            require_permission(&actor, permission)?;
        }
    }
    Ok(Json(IntrospectResponse {
        active: true,
        user_id: actor.user_id,
        email: actor.email,
        session_id: actor.session_id,
        roles: actor.roles,
        permissions: actor.permissions,
        mfa_verified: actor.mfa_verified,
    }))
}
async fn admin_actor(state: &AppState, headers: &HeaderMap, write: bool) -> ApiResult<Actor> {
    service(state, headers, true)?;
    let headers = credentials(headers)?;
    let actor = if write {
        mutation(state, &headers).await?
    } else {
        authenticate(state, &headers).await?
    };
    require_permission(&actor, if write { "users:write" } else { "users:read" })?;
    Ok(actor)
}
pub(super) async fn users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(search): Query<SearchUsersRequest>,
) -> ApiResult<Json<UsersResponse>> {
    admin_actor(&state, &headers, false).await?;
    let query = search.query.unwrap_or_default();
    if query.len() > 254 {
        return Err(ApiError::bad("invalid_query"));
    }
    let rows=sqlx::query("SELECT u.id,u.email,u.is_verified,u.is_banned,u.ban_reason,u.created_at,COALESCE(m.is_enabled,false) mfa_enabled,COALESCE(array_agg(r.slug) FILTER (WHERE r.slug IS NOT NULL),'{}') roles FROM users u LEFT JOIN mfa_secrets m ON m.user_id=u.id LEFT JOIN user_roles ur ON ur.user_id=u.id AND (ur.expires_at IS NULL OR ur.expires_at>now()) LEFT JOIN roles r ON r.id=ur.role_id WHERE u.email ILIKE '%'||$1||'%' OR u.id::text=$1 GROUP BY u.id,m.is_enabled ORDER BY u.created_at DESC LIMIT 100").bind(query).fetch_all(&state.db).await?;
    Ok(Json(UsersResponse {
        users: rows
            .into_iter()
            .map(|r| UserSummary {
                id: r.get("id"),
                email: r.get("email"),
                is_verified: r.get("is_verified"),
                is_banned: r.get("is_banned"),
                ban_reason: r.get("ban_reason"),
                created_at: r.get("created_at"),
                mfa_enabled: r.get("mfa_enabled"),
                roles: r.get("roles"),
            })
            .collect(),
    }))
}
pub(super) async fn ban(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(uid): Path<Uuid>,
    Json(body): Json<BanRequest>,
) -> ApiResult<Json<BanResponse>> {
    let actor = admin_actor(&state, &headers, true).await?;
    if uid == actor.user_id {
        return Err(ApiError::bad("cannot_ban_self"));
    }
    let reason = body.reason.unwrap_or_default().trim().to_owned();
    if reason.is_empty() || reason.len() > 500 {
        return Err(ApiError::bad("ban_reason_required"));
    }
    let mut tx = state.db.begin().await?;
    sqlx::query("SELECT id FROM users WHERE id=ANY($1) ORDER BY id FOR UPDATE")
        .bind(vec![actor.user_id, uid])
        .fetch_all(&mut *tx)
        .await?;
    lock_authorized_actor(&mut tx, &actor, false, Some("users:write")).await?;
    let count =
        sqlx::query("UPDATE users SET is_banned=true,ban_reason=$2,updated_at=now() WHERE id=$1")
            .bind(uid)
            .bind(&reason)
            .execute(&mut *tx)
            .await?;
    if count.rows_affected() != 1 {
        return Err(ApiError::bad("user_not_found"));
    }
    revoke_tx(&state, &mut tx, uid, None, "user_banned", &headers).await?;
    sqlx::query(
        "UPDATE identity_challenges SET consumed_at=now() WHERE user_id=$1 AND consumed_at IS NULL",
    )
    .bind(uid)
    .execute(&mut *tx)
    .await?;
    enqueue(
        &mut tx,
        &state.crypto,
        "identity.user_banned",
        uid,
        json!({"user_id":uid,"reason":reason}),
        trace(&headers),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(BanResponse {
        user_id: uid,
        is_banned: true,
    }))
}
pub(super) async fn unban(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(uid): Path<Uuid>,
) -> ApiResult<Json<BanResponse>> {
    let actor = admin_actor(&state, &headers, true).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query("SELECT id FROM users WHERE id=ANY($1) ORDER BY id FOR UPDATE")
        .bind(vec![actor.user_id, uid])
        .fetch_all(&mut *tx)
        .await?;
    lock_authorized_actor(&mut tx, &actor, false, Some("users:write")).await?;
    let count = sqlx::query(
        "UPDATE users SET is_banned=false,ban_reason=NULL,updated_at=now() WHERE id=$1",
    )
    .bind(uid)
    .execute(&mut *tx)
    .await?;
    if count.rows_affected() != 1 {
        return Err(ApiError::bad("user_not_found"));
    }
    enqueue(
        &mut tx,
        &state.crypto,
        "identity.user_unbanned",
        uid,
        json!({"user_id":uid}),
        trace(&headers),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(BanResponse {
        user_id: uid,
        is_banned: false,
    }))
}
