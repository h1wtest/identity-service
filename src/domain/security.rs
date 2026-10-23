use crate::ApiResult;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SessionAuthority {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub banned: bool,
    pub active: bool,
    pub expires_at: DateTime<Utc>,
    pub reauthenticated_at: Option<DateTime<Utc>>,
    pub mfa_verified: bool,
    pub mfa_verified_at: Option<DateTime<Utc>>,
}
#[derive(Clone, Copy)]
pub struct AuthorizationRequirement<'a> {
    pub fresh_password: bool,
    pub permission: Option<&'a str>,
}
impl SessionAuthority {
    pub fn live(&self, now: DateTime<Utc>) -> bool {
        !self.banned && self.active && self.expires_at > now
    }
    pub fn password_fresh(&self, now: DateTime<Utc>) -> bool {
        self.reauthenticated_at
            .map(|value| value > now - chrono::Duration::minutes(5))
            .unwrap_or(false)
    }
    pub fn mfa_fresh(&self, now: DateTime<Utc>) -> bool {
        self.mfa_verified
            && self
                .mfa_verified_at
                .map(|value| value > now - chrono::Duration::minutes(15))
                .unwrap_or(false)
    }
}

/// A unit-of-work port: implementations must hold user then session locks until commit.
#[async_trait::async_trait]
pub trait SecurityTransaction: Send {
    async fn authority(
        &mut self,
        user_id: Uuid,
        session_id: Uuid,
    ) -> ApiResult<Option<SessionAuthority>>;
    async fn permission(&mut self, user_id: Uuid, permission: &str) -> ApiResult<bool>;
    async fn replace_password(
        &mut self,
        user_id: Uuid,
        expected_hash: &str,
        new_hash: &str,
    ) -> ApiResult<bool>;
    async fn revoke_sessions(
        &mut self,
        user_id: Uuid,
        session_id: Option<Uuid>,
        reason: &str,
    ) -> ApiResult<Vec<Uuid>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn revoked_or_banned_authority_is_never_live() {
        let now = Utc::now();
        let mut authority = SessionAuthority {
            user_id: Uuid::nil(),
            session_id: Uuid::nil(),
            banned: false,
            active: true,
            expires_at: now + chrono::Duration::hours(1),
            reauthenticated_at: Some(now),
            mfa_verified: true,
            mfa_verified_at: Some(now),
        };
        assert!(authority.live(now));
        authority.active = false;
        assert!(!authority.live(now));
        authority.active = true;
        authority.banned = true;
        assert!(!authority.live(now));
    }
    #[test]
    fn fresh_password_and_mfa_expire_independently() {
        let now = Utc::now();
        let authority = SessionAuthority {
            user_id: Uuid::nil(),
            session_id: Uuid::nil(),
            banned: false,
            active: true,
            expires_at: now + chrono::Duration::hours(1),
            reauthenticated_at: Some(now - chrono::Duration::minutes(6)),
            mfa_verified: true,
            mfa_verified_at: Some(now - chrono::Duration::minutes(10)),
        };
        assert!(!authority.password_fresh(now));
        assert!(authority.mfa_fresh(now));
    }
}
