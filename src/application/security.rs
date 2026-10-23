use crate::{
    domain::security::{AuthorizationRequirement, SecurityTransaction},
    ApiError, ApiResult,
};
use chrono::Utc;
use uuid::Uuid;

/// Application authorization is evaluated on locked current authority, not an HTTP snapshot.
pub async fn authorize(
    transaction: &mut impl SecurityTransaction,
    user_id: Uuid,
    session_id: Uuid,
    requirement: AuthorizationRequirement<'_>,
) -> ApiResult<()> {
    let authority = transaction
        .authority(user_id, session_id)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    let now = Utc::now();
    if !authority.live(now) {
        return Err(ApiError::unauthorized());
    }
    if requirement.fresh_password && !authority.password_fresh(now) {
        return Err(ApiError::forbidden());
    }
    if let Some(permission) = requirement.permission {
        if !authority.mfa_fresh(now) || !transaction.permission(user_id, permission).await? {
            return Err(ApiError::forbidden());
        }
    }
    Ok(())
}
/// Hashing precedes the transaction; the application rechecks all authority after it.
pub async fn change_password(
    transaction: &mut impl SecurityTransaction,
    user_id: Uuid,
    session_id: Uuid,
    expected_hash: &str,
    new_hash: &str,
) -> ApiResult<Vec<Uuid>> {
    authorize(
        transaction,
        user_id,
        session_id,
        AuthorizationRequirement {
            fresh_password: true,
            permission: None,
        },
    )
    .await?;
    if !transaction
        .replace_password(user_id, expected_hash, new_hash)
        .await?
    {
        return Err(ApiError::unauthorized());
    }
    transaction
        .revoke_sessions(user_id, None, "password_changed")
        .await
}
pub async fn revoke(
    transaction: &mut impl SecurityTransaction,
    user_id: Uuid,
    session_id: Option<Uuid>,
    reason: &str,
) -> ApiResult<Vec<Uuid>> {
    transaction
        .revoke_sessions(user_id, session_id, reason)
        .await
}
