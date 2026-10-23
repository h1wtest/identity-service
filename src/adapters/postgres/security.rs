use crate::{
    domain::security::{SecurityTransaction, SessionAuthority},
    ApiResult,
};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub struct PostgresSecurityTransaction<'a, 'db> {
    pub transaction: &'a mut Transaction<'db, Postgres>,
}
#[async_trait::async_trait]
impl SecurityTransaction for PostgresSecurityTransaction<'_, '_> {
    async fn authority(
        &mut self,
        user_id: Uuid,
        session_id: Uuid,
    ) -> ApiResult<Option<SessionAuthority>> {
        let user: Option<bool> =
            sqlx::query_scalar("SELECT is_banned FROM users WHERE id=$1 FOR UPDATE")
                .bind(user_id)
                .fetch_optional(&mut **self.transaction)
                .await?;
        let Some(banned) = user else { return Ok(None) };
        let session=sqlx::query("SELECT is_active,expires_at,reauthenticated_at,mfa_verified,mfa_verified_at FROM sessions WHERE id=$1 AND user_id=$2 FOR UPDATE")
            .bind(session_id).bind(user_id).fetch_optional(&mut **self.transaction).await?;
        Ok(session.map(|row| SessionAuthority {
            user_id,
            session_id,
            banned,
            active: row.get("is_active"),
            expires_at: row.get("expires_at"),
            reauthenticated_at: row.get("reauthenticated_at"),
            mfa_verified: row.get("mfa_verified"),
            mfa_verified_at: row.get("mfa_verified_at"),
        }))
    }
    async fn permission(&mut self, user_id: Uuid, permission: &str) -> ApiResult<bool> {
        if !crate::rbac::PERMISSIONS.contains(&permission) {
            return Ok(false);
        }
        Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_roles ur JOIN roles r ON r.id=ur.role_id JOIN role_permissions rp ON rp.role_id=ur.role_id JOIN permissions p ON p.id=rp.permission_id JOIN mfa_secrets m ON m.user_id=ur.user_id AND m.is_enabled WHERE ur.user_id=$1 AND p.slug=$2 AND (NOT $3 OR r.slug='owner') AND (ur.expires_at IS NULL OR ur.expires_at>now()))")
            .bind(user_id).bind(permission).bind(crate::rbac::owner_only(permission)).fetch_one(&mut **self.transaction).await?)
    }
    async fn replace_password(
        &mut self,
        user_id: Uuid,
        expected_hash: &str,
        new_hash: &str,
    ) -> ApiResult<bool> {
        Ok(sqlx::query("UPDATE users SET password_hash=$2,updated_at=now() WHERE id=$1 AND password_hash=$3 AND NOT is_banned")
            .bind(user_id).bind(new_hash).bind(expected_hash).execute(&mut **self.transaction).await?.rows_affected()==1)
    }
    async fn revoke_sessions(
        &mut self,
        user_id: Uuid,
        session_id: Option<Uuid>,
        reason: &str,
    ) -> ApiResult<Vec<Uuid>> {
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut **self.transaction)
            .await?;
        sqlx::query("UPDATE oauth_token_families SET revoked_at=COALESCE(revoked_at,now()),revoked_reason=$3 WHERE user_id=$1 AND ($2::uuid IS NULL OR session_id=$2) AND revoked_at IS NULL").bind(user_id).bind(session_id).bind(reason).execute(&mut **self.transaction).await?;
        Ok(sqlx::query_scalar("UPDATE sessions SET is_active=false,revoked_reason=$3 WHERE user_id=$1 AND is_active AND ($2::uuid IS NULL OR id=$2) RETURNING id")
            .bind(user_id).bind(session_id).bind(reason).fetch_all(&mut **self.transaction).await?)
    }
}
