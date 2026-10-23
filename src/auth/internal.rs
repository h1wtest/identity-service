use super::*;
use platform_contracts::http::{
    BanRequest, BanResponse, IntrospectRequest, IntrospectResponse, SearchUsersRequest,
    UserSummary, UsersResponse,
};
fn service(state: &AppState, headers: &HeaderMap, admin: bool) -> ApiResult<()> {
    let token = headers
        .get("x-service-token")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .ok_or_else(ApiError::unauthorized)?;
    let allowed = if admin {
        constant_eq(token, &state.config.admin_internal_token)
    } else {
        [
            &state.config.profile_internal_token,
            &state.config.notification_internal_token,
            &state.config.admin_internal_token,
            &state.config.catalog_internal_token,
            &state.config.billing_internal_token,
            &state.config.subscription_internal_token,
            &state.config.referral_internal_token,
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
    let caller = workload(&state, &headers)?;
    if !scope(caller, body.permission.as_deref().unwrap_or("")) {
        return Err(ApiError::forbidden());
    }
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
        if crate::rbac::OWN_PERMISSIONS.contains(&permission) {
            if !actor.permissions.iter().any(|p| p == permission) {
                return Err(ApiError::forbidden());
            }
        } else {
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
    crate::rbac::serialize(&mut tx).await?;
    sqlx::query("SELECT id FROM users WHERE id=ANY($1) ORDER BY id FOR UPDATE")
        .bind(vec![actor.user_id, uid])
        .fetch_all(&mut *tx)
        .await?;
    lock_authorized_actor(&mut tx, &actor, false, Some("users:write")).await?;
    crate::rbac::protect_owner(&mut tx, &actor, uid, true).await?;
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
    crate::rbac::serialize(&mut tx).await?;
    sqlx::query("SELECT id FROM users WHERE id=ANY($1) ORDER BY id FOR UPDATE")
        .bind(vec![actor.user_id, uid])
        .fetch_all(&mut *tx)
        .await?;
    lock_authorized_actor(&mut tx, &actor, false, Some("users:write")).await?;
    crate::rbac::protect_owner(&mut tx, &actor, uid, false).await?;
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

fn workload(state: &AppState, headers: &HeaderMap) -> ApiResult<&'static str> {
    let token = headers
        .get("x-service-token")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .ok_or_else(ApiError::unauthorized)?;
    for (name, value) in [
        ("profile", &state.config.profile_internal_token),
        ("notification", &state.config.notification_internal_token),
        ("admin", &state.config.admin_internal_token),
        ("catalog", &state.config.catalog_internal_token),
        ("billing", &state.config.billing_internal_token),
        ("subscription", &state.config.subscription_internal_token),
        ("referral", &state.config.referral_internal_token),
    ] {
        if constant_eq(token, value) {
            return Ok(name);
        }
    }
    Err(ApiError::forbidden())
}
fn scope(service: &str, p: &str) -> bool {
    if p.is_empty() || crate::rbac::OWN_PERMISSIONS.contains(&p) || p == "users:self:reauth" {
        return true;
    }
    match service {
        "admin" => matches!(
            p,
            "users:read"
                | "users:write"
                | "users:sessions:revoke"
                | "audit:read"
                | "notifications:read"
                | "notifications:templates:write"
                | "notifications:replay"
        ),
        "profile" => matches!(
            p,
            "notifications:bindings:reset" | "notifications:read" | "notifications:replay"
        ),
        "notification" => p.starts_with("notifications:"),
        "catalog" => p.starts_with("catalog:"),
        "billing" => p.starts_with("billing:"),
        "subscription" => p.starts_with("subscriptions:"),
        "referral" => p.starts_with("referrals:"),
        _ => false,
    }
}
pub(super) async fn introspect_v2(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<IntrospectRequest>,
) -> ApiResult<Json<Value>> {
    let svc = workload(&state, &headers)?;
    let permission = body.permission.clone().unwrap_or_default();
    if !scope(svc, &permission) {
        return Err(ApiError::forbidden());
    }
    let require_reauth = permission == "users:self:reauth";
    let mut body = body;
    if require_reauth {
        body.permission = None;
    }
    let Json(mut result) = introspect(State(state.clone()), headers, Json(body)).await?;
    let row=sqlx::query("SELECT u.is_verified,s.reauthenticated_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.is_active AND s.expires_at>now() AND NOT u.is_banned").bind(result.session_id).fetch_optional(&state.db).await?.ok_or_else(ApiError::unauthorized)?;
    let reauth: Option<DateTime<Utc>> = row.get("reauthenticated_at");
    if require_reauth
        && !reauth
            .map(|v| v > Utc::now() - chrono::Duration::minutes(5))
            .unwrap_or(false)
    {
        return Err(ApiError::forbidden());
    }
    if require_reauth {
        result.permissions.push("users:self:reauth".into());
    }
    sqlx::query("UPDATE sessions SET last_active_at=now() WHERE id=$1 AND last_active_at<=now()-interval '60 seconds'").bind(result.session_id).execute(&state.db).await?;
    let mut value = serde_json::to_value(result).map_err(|_| ApiError::dependency())?;
    value["is_verified"] = json!(row.get::<bool, _>("is_verified"));
    value["reauthenticated_at"] = json!(reauth);
    Ok(Json(value))
}
#[derive(Deserialize)]
pub(super) struct Backfill {
    cursor: Option<Uuid>,
    limit: Option<i64>,
}
pub(super) async fn backfill(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(b): Query<Backfill>,
) -> ApiResult<Json<Value>> {
    if workload(&state, &headers)? != "referral" {
        return Err(ApiError::forbidden());
    }
    let limit = b.limit.unwrap_or(100);
    if !(1..=100).contains(&limit) {
        return Err(ApiError::bad("invalid_limit"));
    }
    let rows=sqlx::query("SELECT id,registration_id,referral_claim_id,created_at FROM users WHERE ($1::uuid IS NULL OR id>$1) ORDER BY id LIMIT $2").bind(b.cursor).bind(limit+1).fetch_all(&state.db).await?;
    let more = rows.len() > limit as usize;
    let items:Vec<Value>=rows.into_iter().take(limit as usize).map(|r|json!({"user_id":r.get::<Uuid,_>("id"),"registration_id":r.get::<Uuid,_>("registration_id"),"referral_claim_id":r.get::<Option<Uuid>,_>("referral_claim_id"),"registered_at":r.get::<DateTime<Utc>,_>("created_at")})).collect();
    let next = if more {
        items
            .last()
            .and_then(|v| v.get("user_id"))
            .cloned()
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    Ok(Json(json!({"items":items,"next_cursor":next})))
}
pub(super) async fn eligibility(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(uid): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let svc = workload(&state, &headers)?;
    if !["profile", "notification", "billing", "subscription"].contains(&svc) {
        return Err(ApiError::forbidden());
    }
    let row = sqlx::query(
        "SELECT email,is_verified,is_banned,registration_locale FROM users WHERE id=$1",
    )
    .bind(uid)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        code: "user_not_found",
    })?;
    let roles:Vec<String>=sqlx::query_scalar("SELECT r.slug FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1 AND (ur.expires_at IS NULL OR ur.expires_at>now())").bind(uid).fetch_all(&state.db).await?;
    let mut permissions:Vec<String>=sqlx::query_scalar("SELECT DISTINCT p.slug FROM user_roles ur JOIN role_permissions rp ON rp.role_id=ur.role_id JOIN permissions p ON p.id=rp.permission_id WHERE ur.user_id=$1 AND (ur.expires_at IS NULL OR ur.expires_at>now())").bind(uid).fetch_all(&state.db).await?;
    permissions.retain(|p| {
        crate::rbac::PERMISSIONS.contains(&p.as_str())
            && (!crate::rbac::owner_only(p) || roles.iter().any(|r| r == "owner"))
    });
    Ok(Json(
        json!({"user_id":uid,"email":row.get::<String,_>("email"),"active":!row.get::<bool,_>("is_banned"),"verified":row.get::<bool,_>("is_verified"),"banned":row.get::<bool,_>("is_banned"),"locale":row.get::<String,_>("registration_locale"),"staff":!roles.is_empty(),"permissions":permissions}),
    ))
}
#[derive(Deserialize)]
pub(super) struct Flow {
    event_id: Uuid,
    r#type: String,
    target: String,
}
pub(super) async fn notification_flow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(uid): Path<Uuid>,
    Query(b): Query<Flow>,
) -> ApiResult<Json<Value>> {
    if workload(&state, &headers)? != "notification" {
        return Err(ApiError::forbidden());
    }
    if ![
        "notification.email_verification",
        "notification.password_reset",
    ]
    .contains(&b.r#type.as_str())
    {
        return Err(ApiError::bad("invalid_event_type"));
    }
    let stored: Option<Value> =
        sqlx::query_scalar("SELECT payload FROM outbox_events WHERE id=$1 AND event_type=$2")
            .bind(b.event_id)
            .bind(&b.r#type)
            .fetch_optional(&state.db)
            .await?;
    let Some(stored) = stored else {
        return Ok(Json(json!({"active":false})));
    };
    let encrypted = stored
        .get("encrypted_payload")
        .and_then(Value::as_str)
        .ok_or_else(ApiError::dependency)?;
    let bytes = state
        .crypto
        .decrypt(&b.event_id.to_string(), encrypted)
        .map_err(|_| ApiError::dependency())?;
    let payload: Value = serde_json::from_slice(&bytes).map_err(|_| ApiError::dependency())?;
    if payload.get("user_id").and_then(Value::as_str) != Some(uid.to_string().as_str()) {
        return Ok(Json(json!({"active":false})));
    }
    if payload.get("email").and_then(Value::as_str) != Some(b.target.as_str()) {
        return Ok(Json(json!({"active":false})));
    }
    let (kind, hash) = if b.r#type == "notification.email_verification" {
        (
            "verify_email",
            digest(&format!(
                "{uid}:{}",
                payload.get("code").and_then(Value::as_str).unwrap_or("")
            )),
        )
    } else {
        (
            "password_reset",
            digest(payload.get("token").and_then(Value::as_str).unwrap_or("")),
        )
    };
    let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM identity_challenges c JOIN users u ON u.id=c.user_id WHERE c.user_id=$1 AND c.kind=$2 AND c.token_hash=$3 AND c.consumed_at IS NULL AND c.expires_at>now() AND NOT u.is_banned AND u.email=$4 AND ($2<>'verify_email' OR NOT u.is_verified))").bind(uid).bind(kind).bind(hash).bind(&b.target).fetch_one(&state.db).await?;
    Ok(Json(json!({"active":active})))
}
#[derive(Deserialize)]
pub(super) struct RevokeReason {
    reason: String,
    #[serde(default)]
    command_id: Option<Uuid>,
}
pub(super) async fn admin_revoke_public(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(uid): Path<Uuid>,
    Json(b): Json<RevokeReason>,
) -> ApiResult<Json<Value>> {
    admin_revoke_impl(&state, &headers, uid, b).await
}
async fn admin_revoke_impl(
    state: &AppState,
    headers: &HeaderMap,
    uid: Uuid,
    b: RevokeReason,
) -> ApiResult<Json<Value>> {
    let reason = crate::rbac::reason(&b.reason)?;
    let actor = mutation(state, headers).await?;
    require_permission(&actor, "users:sessions:revoke")?;
    let mut tx = state.db.begin().await?;
    crate::rbac::serialize(&mut tx).await?;
    sqlx::query("SELECT id FROM users WHERE id=ANY($1) ORDER BY id FOR UPDATE")
        .bind(vec![actor.user_id, uid])
        .fetch_all(&mut *tx)
        .await?;
    lock_authorized_actor(&mut tx, &actor, false, Some("users:sessions:revoke")).await?;
    crate::rbac::session_target(&mut tx, &actor, uid).await?;
    let count = revoke_tx(state, &mut tx, uid, None, "admin_revoked", headers).await?;
    crate::rbac::audit(
        &mut tx,
        &actor,
        "user.sessions.revoke",
        &uid.to_string(),
        reason,
        json!({"revoked":count,"command_id":b.command_id}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"revoked":count})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Command {
    reason: String,
    #[serde(alias = "command_id")]
    idempotency_key: Uuid,
}
pub(super) async fn ban_v2(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
    Json(b): Json<Command>,
) -> ApiResult<Json<Value>> {
    command(&s, &h, id, b, "ban").await
}
pub(super) async fn unban_v2(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
    Json(b): Json<Command>,
) -> ApiResult<Json<Value>> {
    command(&s, &h, id, b, "unban").await
}
pub(super) async fn revoke_v2(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
    Json(b): Json<Command>,
) -> ApiResult<Json<Value>> {
    command(&s, &h, id, b, "revoke").await
}
async fn command(
    s: &AppState,
    h: &HeaderMap,
    id: Uuid,
    b: Command,
    operation: &str,
) -> ApiResult<Json<Value>> {
    service(s, h, true)?;
    let headers = credentials(h)?;
    let a = mutation(s, &headers).await?;
    let permission = if operation == "revoke" {
        "users:sessions:revoke"
    } else {
        "users:write"
    };
    require_permission(&a, permission)?;
    let why = crate::rbac::reason(&b.reason)?;
    let request = json!({"reason":why});
    let mut tx = s.db.begin().await?;
    crate::rbac::serialize(&mut tx).await?;
    sqlx::query("SELECT id FROM users WHERE id=ANY($1) ORDER BY id FOR UPDATE")
        .bind(vec![a.user_id, id])
        .fetch_all(&mut *tx)
        .await?;
    lock_authorized_actor(&mut tx, &a, false, Some(permission)).await?;
    let existing=sqlx::query("SELECT actor_user_id,operation,target,request,result FROM identity_admin_commands WHERE command_id=$1").bind(b.idempotency_key).fetch_optional(&mut *tx).await?;
    if let Some(row) = existing {
        if row.get::<Uuid, _>("actor_user_id") != a.user_id
            || row.get::<String, _>("operation") != operation
            || row.get::<Uuid, _>("target") != id
            || row.get::<Value, _>("request") != request
        {
            return Err(crate::rbac::conflict("idempotency_conflict"));
        }
        return Ok(Json(row.get("result")));
    }
    let available: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if !available {
        return Err(ApiError::bad("user_not_found"));
    }
    let result = if operation == "revoke" {
        crate::rbac::session_target(&mut tx, &a, id).await?;
        json!({"revoked":revoke_tx(s,&mut tx,id,None,"admin_revoked",&headers).await?})
    } else {
        if id == a.user_id && operation == "ban" {
            return Err(ApiError::bad("cannot_ban_self"));
        }
        crate::rbac::protect_owner(&mut tx, &a, id, operation == "ban").await?;
        let banned = operation == "ban";
        sqlx::query("UPDATE users SET is_banned=$2,ban_reason=CASE WHEN $2 THEN $3 ELSE NULL END,updated_at=now() WHERE id=$1").bind(id).bind(banned).bind(why).execute(&mut *tx).await?;
        if banned {
            revoke_tx(s, &mut tx, id, None, "user_banned", &headers).await?;
            sqlx::query("UPDATE identity_challenges SET consumed_at=now() WHERE user_id=$1 AND consumed_at IS NULL").bind(id).execute(&mut *tx).await?;
        }
        enqueue(
            &mut tx,
            &s.crypto,
            if banned {
                "identity.user_banned"
            } else {
                "identity.user_unbanned"
            },
            id,
            if banned {
                json!({"user_id":id,"reason":why})
            } else {
                json!({"user_id":id})
            },
            trace(&headers),
        )
        .await?;
        json!({"user_id":id,"is_banned":banned})
    };
    sqlx::query("INSERT INTO identity_admin_commands(command_id,actor_user_id,operation,target,request,result) VALUES($1,$2,$3,$4,$5,$6)").bind(b.idempotency_key).bind(a.user_id).bind(operation).bind(id).bind(request).bind(&result).execute(&mut *tx).await?;
    crate::rbac::audit(
        &mut tx,
        &a,
        operation,
        &id.to_string(),
        why,
        json!({"command_id":b.idempotency_key,"result":result}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(result))
}
pub(super) async fn command_status(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    service(&s, &h, true)?;
    let a = authenticate(&s, &credentials(&h)?).await?;
    require_permission(&a, "audit:read")?;
    let result: Option<Value> = sqlx::query_scalar(
        "SELECT result FROM identity_admin_commands WHERE command_id=$1 AND actor_user_id=$2",
    )
    .bind(id)
    .bind(a.user_id)
    .fetch_optional(&s.db)
    .await?;
    Ok(Json(
        json!({"command_id":id,"status":"succeeded","result":result.ok_or(ApiError{status:StatusCode::NOT_FOUND,code:"command_not_found"})?}),
    ))
}
pub(super) async fn user_detail(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    admin_actor(&s, &h, false).await?;
    let row=sqlx::query("SELECT u.id,u.email,u.is_verified,u.is_banned,u.ban_reason,u.created_at,COALESCE(m.is_enabled,false) mfa_enabled FROM users u LEFT JOIN mfa_secrets m ON m.user_id=u.id WHERE u.id=$1").bind(id).fetch_optional(&s.db).await?.ok_or(ApiError{status:StatusCode::NOT_FOUND,code:"user_not_found"})?;
    let roles:Vec<String>=sqlx::query_scalar("SELECT r.slug FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1 AND (ur.expires_at IS NULL OR ur.expires_at>now()) ORDER BY r.slug").bind(id).fetch_all(&s.db).await?;
    Ok(Json(
        json!({"id":id,"email":row.get::<String,_>("email"),"is_verified":row.get::<bool,_>("is_verified"),"is_banned":row.get::<bool,_>("is_banned"),"ban_reason":row.get::<Option<String>,_>("ban_reason"),"created_at":row.get::<DateTime<Utc>,_>("created_at"),"mfa_enabled":row.get::<bool,_>("mfa_enabled"),"roles":roles}),
    ))
}
#[derive(Deserialize)]
pub(super) struct Recipients {
    permission: String,
    cursor: Option<Uuid>,
    limit: Option<i64>,
}
pub(super) async fn notification_recipients(
    State(s): State<AppState>,
    h: HeaderMap,
    Query(b): Query<Recipients>,
) -> ApiResult<Json<Value>> {
    if workload(&s, &h)? != "notification"
        || !crate::rbac::PERMISSIONS.contains(&b.permission.as_str())
    {
        return Err(ApiError::forbidden());
    }
    let limit = b.limit.unwrap_or(100);
    if !(1..=100).contains(&limit) {
        return Err(ApiError::bad("invalid_limit"));
    }
    let ids:Vec<Uuid>=sqlx::query_scalar("SELECT DISTINCT u.id FROM users u JOIN user_roles ur ON ur.user_id=u.id JOIN role_permissions rp ON rp.role_id=ur.role_id JOIN permissions p ON p.id=rp.permission_id WHERE NOT u.is_banned AND u.is_verified AND p.slug=$1 AND (ur.expires_at IS NULL OR ur.expires_at>now()) AND ($2::uuid IS NULL OR u.id>$2) ORDER BY u.id LIMIT $3").bind(&b.permission).bind(b.cursor).bind(limit+1).fetch_all(&s.db).await?;
    let more = ids.len() > limit as usize;
    let mut items = Vec::new();
    let mut next = None;
    for id in ids.into_iter().take(limit as usize) {
        let Json(value) = eligibility(State(s.clone()), h.clone(), Path(id)).await?;
        next = Some(id);
        items.push(value)
    }
    Ok(Json(
        json!({"items":items,"next_cursor":if more{next}else{None}}),
    ))
}
