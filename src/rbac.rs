// SPDX-License-Identifier: MIT
use crate::{
    auth::{self, Actor},
    ApiError, ApiResult, AppState,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub const PERMISSIONS: &[&str] = &[
    "users:read",
    "users:write",
    "users:sessions:revoke",
    "roles:read",
    "roles:write",
    "roles:assign",
    "catalog:read",
    "catalog:write",
    "catalog:publish",
    "billing:read",
    "billing:status:read",
    "billing:resolve",
    "subscriptions:read",
    "subscriptions:write",
    "subscriptions:compensate",
    "subscriptions:close",
    "referrals:read",
    "referrals:rates:write",
    "referrals:payouts:decide",
    "notifications:read",
    "notifications:templates:write",
    "notifications:replay",
    "notifications:bindings:reset",
    "audit:read",
    "oauth:clients:write",
];
pub const OWN_PERMISSIONS: &[&str] = &[
    "users:self:read",
    "users:self:update",
    "users:sessions:self:read",
    "users:sessions:self:revoke",
];
pub fn known_permission(p: &str) -> bool {
    PERMISSIONS.contains(&p) || OWN_PERMISSIONS.contains(&p)
}
pub fn owner_only(p: &str) -> bool {
    p.starts_with("roles:") || p == "oauth:clients:write"
}
pub fn conflict(code: &'static str) -> ApiError {
    ApiError {
        status: StatusCode::CONFLICT,
        code,
    }
}
pub fn reason(v: &str) -> ApiResult<&str> {
    let v = v.trim();
    if v.is_empty() || v.len() > 500 {
        Err(ApiError::bad("reason_required"))
    } else {
        Ok(v)
    }
}
pub async fn serialize(tx: &mut Transaction<'_, Postgres>) -> ApiResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(742915830)")
        .execute(&mut **tx)
        .await?;
    Ok(())
}
pub async fn owner(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    permission: &str,
    write: bool,
) -> ApiResult<()> {
    auth::lock_authorized_actor(tx, actor, write, Some(permission)).await?;
    let yes:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1 AND r.slug='owner' AND (ur.expires_at IS NULL OR ur.expires_at>now()))").bind(actor.user_id).fetch_one(&mut **tx).await?;
    if !yes {
        return Err(ApiError::forbidden());
    }
    Ok(())
}
pub async fn protect_owner(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    target: Uuid,
    removing: bool,
) -> ApiResult<()> {
    let target_owner:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1 AND r.slug='owner' AND (ur.expires_at IS NULL OR ur.expires_at>now()))").bind(target).fetch_one(&mut **tx).await?;
    if target_owner {
        let current_owner:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1 AND r.slug='owner' AND (ur.expires_at IS NULL OR ur.expires_at>now()))").bind(actor.user_id).fetch_one(&mut **tx).await?;
        if !current_owner {
            return Err(ApiError::forbidden());
        }
        if removing {
            let count:i64=sqlx::query_scalar("SELECT count(DISTINCT ur.user_id) FROM user_roles ur JOIN roles r ON r.id=ur.role_id JOIN users u ON u.id=ur.user_id WHERE r.slug='owner' AND NOT u.is_banned AND (ur.expires_at IS NULL OR ur.expires_at>now())").fetch_one(&mut **tx).await?;
            if count <= 1 {
                return Err(conflict("last_owner"));
            }
        }
    }
    Ok(())
}

pub async fn session_target(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    target: Uuid,
) -> ApiResult<()> {
    let actor_roles:Vec<String>=sqlx::query_scalar("SELECT r.slug FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1 AND (ur.expires_at IS NULL OR ur.expires_at>now())").bind(actor.user_id).fetch_all(&mut **tx).await?;
    let target_roles:Vec<String>=sqlx::query_scalar("SELECT r.slug FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1 AND (ur.expires_at IS NULL OR ur.expires_at>now())").bind(target).fetch_all(&mut **tx).await?;
    let allowed = actor_roles.iter().any(|r| r == "owner")
        || (actor_roles.iter().any(|r| r == "admin") && !target_roles.iter().any(|r| r == "owner"))
        || (actor_roles.iter().any(|r| r == "support") && target_roles.is_empty());
    if !allowed {
        return Err(ApiError::forbidden());
    }
    Ok(())
}
pub async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    a: &Actor,
    operation: &str,
    target: &str,
    reason: &str,
    details: Value,
) -> ApiResult<()> {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO identity_admin_audit(id,actor_user_id,actor_session_id,operation,target,reason,details) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(id).bind(a.user_id).bind(a.session_id).bind(operation).bind(target).bind(reason).bind(details).execute(&mut **tx).await?;
    let target_type = if operation == "role.permissions" {
        "role"
    } else if operation.starts_with("oauth.client.") {
        "oauth_client"
    } else {
        "user"
    };
    let e = platform_contracts::eventsv2::Envelope {
        schema_version: 2,
        event_id: id,
        event_type: "identity.admin_action_recorded".into(),
        producer: "identity".into(),
        aggregate_type: "identity_admin_action".into(),
        aggregate_id: id,
        aggregate_version: 1,
        occurred_at: chrono::Utc::now(),
        correlation_id: None,
        causation_id: None,
        traceparent: None,
        payload: Some(
            json!({"audit_id":id,"actor_user_id":a.user_id,"actor_session_id":a.session_id,"operation":operation,"target_type":target_type,"target_id":target,"reason":reason}),
        ),
        encrypted_payload: None,
    };
    e.validate()
        .map_err(|_| ApiError::bad("invalid_event_payload"))?;
    sqlx::query("INSERT INTO outbox_events(id,event_type,aggregate_id,topic,payload) VALUES($1,'identity.admin_action_recorded',$2,'identity.events.v2',$3)").bind(id).bind(id.to_string()).bind(serde_json::to_value(e).map_err(|_|ApiError::dependency())?).execute(&mut **tx).await?;
    Ok(())
}
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/admin/roles", get(roles))
        .route(
            "/api/v1/admin/roles/{slug}/permissions",
            axum::routing::put(permissions),
        )
        .route(
            "/api/v1/admin/users/{id}/roles",
            get(assignments).put(assign),
        )
        .with_state(state)
}
async fn roles(State(s): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let a = auth::authenticate(&s, &headers).await?;
    auth::require_permission(&a, "roles:read")?;
    let rows=sqlx::query("SELECT r.slug,r.name,r.version,COALESCE(array_agg(p.slug ORDER BY p.slug) FILTER(WHERE p.slug IS NOT NULL),'{}') permissions FROM roles r LEFT JOIN role_permissions rp ON rp.role_id=r.id LEFT JOIN permissions p ON p.id=rp.permission_id GROUP BY r.id ORDER BY r.slug").fetch_all(&s.db).await?;
    Ok(Json(
        json!({"roles":rows.into_iter().map(|r|json!({"slug":r.get::<String,_>("slug"),"name":r.get::<String,_>("name"),"version":r.get::<i64,_>("version"),"permissions":r.get::<Vec<String>,_>("permissions")})).collect::<Vec<_>>(),"permissions":PERMISSIONS}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PermissionWrite {
    permissions: Vec<String>,
    expected_version: i64,
    reason: String,
}
async fn permissions(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Json(b): Json<PermissionWrite>,
) -> ApiResult<Json<Value>> {
    let why = reason(&b.reason)?;
    let a = auth::mutation(&s, &headers).await?;
    auth::require_permission(&a, "roles:write")?;
    if slug == "owner" {
        return Err(ApiError::bad("owner_permissions_immutable"));
    }
    if !["admin", "support"].contains(&slug.as_str())
        || b.permissions
            .iter()
            .any(|p| !PERMISSIONS.contains(&p.as_str()) || owner_only(p))
    {
        return Err(ApiError::bad("invalid_permission"));
    }
    if slug == "support"
        && b.permissions.iter().any(|p| {
            ![
                "users:read",
                "users:sessions:revoke",
                "catalog:read",
                "billing:status:read",
                "subscriptions:read",
                "notifications:read",
                "notifications:bindings:reset",
            ]
            .contains(&p.as_str())
        })
    {
        return Err(ApiError::bad("invalid_permission"));
    }
    let mut tx = s.db.begin().await?;
    serialize(&mut tx).await?;
    owner(&mut tx, &a, "roles:write", true).await?;
    let role: Option<(Uuid, i64)> =
        sqlx::query_as("SELECT id,version FROM roles WHERE slug=$1 FOR UPDATE")
            .bind(&slug)
            .fetch_optional(&mut *tx)
            .await?;
    let (id, version) = role.ok_or_else(|| ApiError::bad("invalid_role"))?;
    if version != b.expected_version {
        return Err(conflict("version_conflict"));
    }
    sqlx::query("DELETE FROM role_permissions WHERE role_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO role_permissions SELECT $1,id FROM permissions WHERE slug=ANY($2)")
        .bind(id)
        .bind(&b.permissions)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE roles SET version=version+1 WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        &a,
        "role.permissions",
        &slug,
        why,
        json!({"permissions":b.permissions}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"slug":slug,"version":version+1,"permissions":b.permissions}),
    ))
}
async fn assignments(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let a = auth::authenticate(&s, &headers).await?;
    auth::require_permission(&a, "roles:read")?;
    let row=sqlx::query("SELECT u.role_version,COALESCE((SELECT array_agg(r.slug ORDER BY r.slug) FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=u.id AND (ur.expires_at IS NULL OR ur.expires_at>now())),'{}'::text[]) roles FROM users u WHERE u.id=$1").bind(id).fetch_optional(&s.db).await?.ok_or(ApiError{status:StatusCode::NOT_FOUND,code:"user_not_found"})?;
    let roles: Vec<String> = row.get("roles");
    let version: i64 = row.get("role_version");
    Ok(Json(
        json!({"user_id":id,"roles":roles,"role_version":version}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assign {
    roles: Vec<String>,
    reason: String,
    expected_version: i64,
}
async fn assign(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(b): Json<Assign>,
) -> ApiResult<Json<Value>> {
    let why = reason(&b.reason)?;
    if b.roles.len() > 3
        || b.roles
            .iter()
            .any(|r| !["owner", "admin", "support"].contains(&r.as_str()))
    {
        return Err(ApiError::bad("invalid_role"));
    }
    let a = auth::mutation(&s, &headers).await?;
    auth::require_permission(&a, "roles:assign")?;
    let mut tx = s.db.begin().await?;
    serialize(&mut tx).await?;
    sqlx::query("SELECT id FROM users WHERE id=ANY($1) ORDER BY id FOR UPDATE")
        .bind(vec![a.user_id, id])
        .fetch_all(&mut *tx)
        .await?;
    owner(&mut tx, &a, "roles:assign", true).await?;
    protect_owner(&mut tx, &a, id, !b.roles.iter().any(|x| x == "owner")).await?;
    let active: Option<bool> = sqlx::query_scalar("SELECT NOT is_banned FROM users WHERE id=$1")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    if active != Some(true) {
        return Err(ApiError::bad("user_unavailable"));
    }
    let version: i64 = sqlx::query_scalar("SELECT role_version FROM users WHERE id=$1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if version != b.expected_version {
        return Err(conflict("version_conflict"));
    }
    sqlx::query("DELETE FROM user_roles WHERE user_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO user_roles(user_id,role_id,granted_by) SELECT $1,id,$3 FROM roles WHERE slug=ANY($2)").bind(id).bind(&b.roles).bind(a.user_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE users SET role_version=role_version+1 WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        &a,
        "user.roles",
        &id.to_string(),
        why,
        json!({"roles":b.roles,"role_version":version+1}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"user_id":id,"roles":b.roles,"role_version":version+1}),
    ))
}
