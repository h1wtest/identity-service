// SPDX-License-Identifier: MIT
use crate::{ApiError, ApiResult, AppState};
use serde_json::{json, Value};
use uuid::Uuid;

/// No-code registration never constructs a client or depends on referral availability.
pub async fn prepare(
    s: &AppState,
    user_id: Uuid,
    registration_id: Uuid,
    code: Option<&str>,
) -> ApiResult<Option<(Uuid, chrono::DateTime<chrono::Utc>)>> {
    let Some(code) = code else { return Ok(None) };
    let code = code.trim();
    if code.is_empty() || code.len() > 128 {
        return Err(ApiError::bad("invalid_referral_code"));
    }
    if s.config.identity_internal_token.is_empty()
        || s.config.referral_url.is_empty()
        || s.config.internal_ca_file.is_empty()
    {
        return Err(ApiError::dependency());
    }
    let pem = tokio::fs::read(&s.config.internal_ca_file)
        .await
        .map_err(|_| ApiError::dependency())?;
    let ca = reqwest::Certificate::from_pem(&pem).map_err(|_| ApiError::dependency())?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .connect_timeout(std::time::Duration::from_secs(2))
        .add_root_certificate(ca)
        .build()
        .map_err(|_| ApiError::dependency())?;
    let body = serde_json::to_vec(
        &json!({"user_id":user_id,"registration_id":registration_id,"code":code}),
    )
    .map_err(|_| ApiError::dependency())?;
    let mut response = client
        .post(format!(
            "{}/internal/v2/referral-claims",
            s.config.referral_url.trim_end_matches('/')
        ))
        .header("x-service-token", &s.config.identity_internal_token)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|_| ApiError::dependency())?;
    let status = response.status();
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ApiError::dependency())? {
        if data.len() + chunk.len() > 16384 {
            return Err(ApiError::dependency());
        }
        data.extend_from_slice(&chunk)
    }
    let body: Value = serde_json::from_slice(&data).map_err(|_| ApiError::dependency())?;
    if !status.is_success() {
        return Err(if status.as_u16() == 400 {
            ApiError::bad("invalid_referral_code")
        } else if status.as_u16() == 409 {
            crate::rbac::conflict("referral_binding_conflict")
        } else {
            ApiError::dependency()
        });
    }
    let id = body
        .get("id")
        .and_then(Value::as_str)
        .and_then(|id| Uuid::parse_str(id).ok())
        .ok_or_else(ApiError::dependency)?;
    if body.get("user_id").and_then(Value::as_str) != Some(user_id.to_string().as_str())
        || body.get("registration_id").and_then(Value::as_str)
            != Some(registration_id.to_string().as_str())
    {
        return Err(ApiError::dependency());
    }
    let expires = body
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
        .map(|v| v.with_timezone(&chrono::Utc))
        .ok_or_else(ApiError::dependency)?;
    if expires <= chrono::Utc::now() {
        return Err(ApiError::bad("referral_claim_expired"));
    }
    Ok(Some((id, expires)))
}
