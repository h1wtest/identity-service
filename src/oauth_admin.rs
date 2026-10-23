// SPDX-License-Identifier: MIT
use crate::{auth, rbac, ApiError, ApiResult, AppState};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use uuid::Uuid;

pub fn router(s: AppState) -> Router {
    Router::new()
        .route("/api/v1/admin/oauth/clients", get(list).post(create))
        .route("/api/v1/admin/oauth/clients/{id}/rotate", post(rotate))
        .route("/api/v1/admin/oauth/clients/{id}/revoke", post(revoke))
        .with_state(s)
}
fn view(r: &sqlx::postgres::PgRow) -> Value {
    json!({"client_id":r.get::<String,_>("client_id"),"client_name":r.get::<String,_>("client_name"),"redirect_uris":r.get::<Vec<String>,_>("redirect_uris"),"allowed_scopes":r.get::<Vec<String>,_>("allowed_scopes"),"is_public":r.get::<bool,_>("is_public"),"trusted_first_party":r.get::<bool,_>("trusted_first_party"),"revoked_at":r.get::<Option<DateTime<Utc>>,_>("revoked_at")})
}
async fn list(State(s): State<AppState>, h: HeaderMap) -> ApiResult<Json<Value>> {
    let a = auth::authenticate(&s, &h).await?;
    auth::require_permission(&a, "oauth:clients:write")?;
    let rows=sqlx::query("SELECT client_id,client_name,redirect_uris,allowed_scopes,is_public,trusted_first_party,revoked_at FROM oauth_clients ORDER BY client_id").fetch_all(&s.db).await?;
    Ok(Json(
        json!({"items":rows.iter().map(view).collect::<Vec<_>>()}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    client_name: String,
    redirect_uris: Vec<String>,
    allowed_scopes: Vec<String>,
    is_public: bool,
    trusted_first_party: bool,
    reason: String,
}
fn redirects(v: &[String]) -> ApiResult<()> {
    if v.is_empty() || v.len() > 20 {
        return Err(ApiError::bad("invalid_redirect_uri"));
    }
    for value in v {
        let u = url::Url::parse(value).map_err(|_| ApiError::bad("invalid_redirect_uri"))?;
        if value.len() > 2048
            || value.contains('*')
            || u.scheme() != "https"
            || u.host_str().is_none()
            || u.fragment().is_some()
            || !u.username().is_empty()
            || u.password().is_some()
        {
            return Err(ApiError::bad("invalid_redirect_uri"));
        }
    }
    Ok(())
}
async fn create(
    State(s): State<AppState>,
    h: HeaderMap,
    Json(b): Json<Create>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let why = rbac::reason(&b.reason)?;
    if b.client_name.trim().is_empty() || b.client_name.len() > 200 {
        return Err(ApiError::bad("invalid_client_name"));
    }
    redirects(&b.redirect_uris)?;
    if !b.allowed_scopes.iter().any(|x| x == "openid")
        || b.allowed_scopes.len() > 4
        || b.allowed_scopes
            .iter()
            .any(|x| !crate::domain::oauth::SUPPORTED_SCOPES.contains(&x.as_str()))
    {
        return Err(ApiError::bad("invalid_scope"));
    }
    let a = auth::mutation(&s, &h).await?;
    auth::require_permission(&a, "oauth:clients:write")?;
    let secret = if b.is_public {
        None
    } else {
        Some(crate::security::random_token())
    };
    let hash = match secret.as_ref() {
        Some(v) => Some(auth::hash_password(&s, v.clone()).await?),
        None => None,
    };
    let id = format!("client-{}", Uuid::now_v7());
    let mut tx = s.db.begin().await?;
    rbac::serialize(&mut tx).await?;
    rbac::owner(&mut tx, &a, "oauth:clients:write", true).await?;
    sqlx::query("INSERT INTO oauth_clients(client_id,client_name,client_secret_hash,redirect_uris,allowed_scopes,is_public,trusted_first_party) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(&id).bind(&b.client_name).bind(hash).bind(&b.redirect_uris).bind(&b.allowed_scopes).bind(b.is_public).bind(b.trusted_first_party).execute(&mut *tx).await?;
    rbac::audit(&mut tx,&a,"oauth.client.create",&id,why,json!({"redirect_uris":b.redirect_uris,"allowed_scopes":b.allowed_scopes,"is_public":b.is_public,"trusted_first_party":b.trusted_first_party})).await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"client_id":id,"client_name":b.client_name,"redirect_uris":b.redirect_uris,"allowed_scopes":b.allowed_scopes,"is_public":b.is_public,"trusted_first_party":b.trusted_first_party,"revoked_at":null,"client_secret":secret}),
        ),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reason {
    reason: String,
}
async fn rotate(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(b): Json<Reason>,
) -> ApiResult<Json<Value>> {
    let why = rbac::reason(&b.reason)?;
    let a = auth::mutation(&s, &h).await?;
    auth::require_permission(&a, "oauth:clients:write")?;
    let secret = crate::security::random_token();
    let hash = auth::hash_password(&s, secret.clone()).await?;
    let mut tx = s.db.begin().await?;
    rbac::serialize(&mut tx).await?;
    sqlx::query("SELECT client_id FROM oauth_clients WHERE client_id=$1 FOR UPDATE")
        .bind(&id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| ApiError::bad("client_unavailable"))?;
    rbac::owner(&mut tx, &a, "oauth:clients:write", true).await?;
    let count=sqlx::query("UPDATE oauth_clients SET client_secret_hash=$2,updated_at=now() WHERE client_id=$1 AND NOT is_public AND revoked_at IS NULL").bind(&id).bind(hash).execute(&mut *tx).await?.rows_affected();
    if count != 1 {
        return Err(ApiError::bad("client_unavailable"));
    }
    rbac::audit(&mut tx, &a, "oauth.client.rotate", &id, why, json!({})).await?;
    tx.commit().await?;
    Ok(Json(json!({"client_id":id,"client_secret":secret})))
}
async fn revoke(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(b): Json<Reason>,
) -> ApiResult<Json<Value>> {
    let why = rbac::reason(&b.reason)?;
    let a = auth::mutation(&s, &h).await?;
    auth::require_permission(&a, "oauth:clients:write")?;
    let mut tx = s.db.begin().await?;
    rbac::serialize(&mut tx).await?;
    sqlx::query("SELECT client_id FROM oauth_clients WHERE client_id=$1 FOR UPDATE")
        .bind(&id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| ApiError::bad("client_not_found"))?;
    rbac::owner(&mut tx, &a, "oauth:clients:write", true).await?;
    let count=sqlx::query("UPDATE oauth_clients SET revoked_at=COALESCE(revoked_at,now()),updated_at=now() WHERE client_id=$1").bind(&id).execute(&mut *tx).await?.rows_affected();
    if count != 1 {
        return Err(ApiError::bad("client_not_found"));
    }
    sqlx::query("UPDATE oauth_token_families SET revoked_at=COALESCE(revoked_at,now()),revoked_reason='client_revoked' WHERE client_id=$1").bind(&id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM oauth_consents WHERE client_id=$1")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    rbac::audit(&mut tx, &a, "oauth.client.revoke", &id, why, json!({})).await?;
    tx.commit().await?;
    Ok(Json(json!({"client_id":id,"revoked":true})))
}
