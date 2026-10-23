// SPDX-License-Identifier: MIT
use crate::{auth, ApiError, ApiResult, AppState};
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

pub fn router(s: AppState) -> Router {
    Router::new()
        .route("/api/v1/auth/oauth/grants", get(list))
        .route(
            "/api/v1/auth/oauth/grants/{client_id}",
            axum::routing::delete(revoke),
        )
        .with_state(s)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    limit: Option<i64>,
    cursor: Option<String>,
}
fn cursor(value: Option<&str>) -> ApiResult<Option<String>> {
    let Some(value) = value else { return Ok(None) };
    if value.is_empty() || value.len() > 256 {
        return Err(ApiError::bad("invalid_cursor"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::bad("invalid_cursor"))?;
    let text = String::from_utf8(decoded).map_err(|_| ApiError::bad("invalid_cursor"))?;
    if text.is_empty()
        || text.len() > 100
        || text.chars().any(char::is_control)
        || URL_SAFE_NO_PAD.encode(text.as_bytes()) != value
    {
        return Err(ApiError::bad("invalid_cursor"));
    }
    Ok(Some(text))
}
async fn list(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> ApiResult<Json<Value>> {
    let actor = auth::authenticate(&s, &headers).await?;
    let limit = page.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(ApiError::bad("invalid_limit"));
    }
    let after = cursor(page.cursor.as_deref())?;
    let rows=sqlx::query("WITH entries AS (SELECT c.client_id,c.client_name,c.trusted_first_party,g.scopes,g.updated_at AS granted_at,g.updated_at AS last_used_at FROM oauth_consents g JOIN oauth_clients c ON c.client_id=g.client_id WHERE g.user_id=$1 AND c.revoked_at IS NULL UNION ALL SELECT c.client_id,c.client_name,c.trusted_first_party,string_to_array(f.scope,' '),f.created_at,GREATEST(f.created_at,COALESCE((SELECT max(r.created_at) FROM oauth_refresh_tokens r WHERE r.family_id=f.id),f.created_at)) FROM oauth_token_families f JOIN oauth_clients c ON c.client_id=f.client_id JOIN sessions s ON s.id=f.session_id WHERE f.user_id=$1 AND f.revoked_at IS NULL AND f.expires_at>now() AND s.is_active AND s.expires_at>now() AND c.revoked_at IS NULL), grouped AS (SELECT client_id,client_name,trusted_first_party,min(granted_at) granted_at,max(last_used_at) last_used_at,array_agg(DISTINCT scope ORDER BY scope) FILTER(WHERE scope IN ('openid','email','profile','offline_access')) scopes FROM entries CROSS JOIN LATERAL unnest(scopes) AS item(scope) GROUP BY client_id,client_name,trusted_first_party) SELECT * FROM grouped WHERE ($2::text IS NULL OR client_id COLLATE \"C\">$2 COLLATE \"C\") ORDER BY client_id COLLATE \"C\" LIMIT $3")
        .bind(actor.user_id).bind(after).bind(limit+1).fetch_all(&s.db).await?;
    let more = rows.len() > limit as usize;
    let mut items = Vec::new();
    let mut next = None;
    for row in rows.into_iter().take(limit as usize) {
        let id: String = row.get("client_id");
        next = Some(URL_SAFE_NO_PAD.encode(id.as_bytes()));
        items.push(json!({"client_id":id,"client_name":row.get::<String,_>("client_name"),"scopes":row.get::<Option<Vec<String>>,_>("scopes").unwrap_or_default(),"trusted_first_party":row.get::<bool,_>("trusted_first_party"),"granted_at":row.get::<DateTime<Utc>,_>("granted_at"),"last_used_at":row.get::<DateTime<Utc>,_>("last_used_at")}));
    }
    Ok(Json(
        json!({"items":items,"next_cursor":if more{next}else{None}}),
    ))
}
async fn revoke(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    if id.is_empty() || id.len() > 100 || id.chars().any(char::is_control) {
        return Err(ApiError::bad("invalid_client"));
    }
    let actor = auth::mutation(&s, &headers).await?;
    let mut tx = s.db.begin().await?;
    // All grant issuance/revocation follows client -> user -> session -> family.
    sqlx::query("SELECT client_id FROM oauth_clients WHERE client_id=$1 FOR UPDATE")
        .bind(&id)
        .fetch_optional(&mut *tx)
        .await?;
    auth::lock_authorized_actor(&mut tx, &actor, false, None).await?;
    sqlx::query("DELETE FROM oauth_consents WHERE user_id=$1 AND client_id=$2")
        .bind(actor.user_id)
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE oauth_token_families SET revoked_at=COALESCE(revoked_at,now()),revoked_reason='user_grant_revoked' WHERE user_id=$1 AND client_id=$2 AND revoked_at IS NULL").bind(actor.user_id).bind(&id).execute(&mut *tx).await?;
    // Preserve consumed proof/reuse history; unspent codes can no longer redeem.
    sqlx::query("UPDATE oauth_authorization_codes SET expires_at=LEAST(expires_at,now()) WHERE user_id=$1 AND client_id=$2 AND consumed_at IS NULL").bind(actor.user_id).bind(&id).execute(&mut *tx).await?;
    sqlx::query("UPDATE oauth_consent_requests SET consumed_at=now() WHERE user_id=$1 AND client_id=$2 AND consumed_at IS NULL").bind(actor.user_id).bind(&id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"client_id":id,"revoked":true})))
}
