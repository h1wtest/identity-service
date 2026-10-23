use crate::{domain::oauth::*, security::Crypto};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::sync::Arc;
use uuid::Uuid;

pub struct PgGrantStore {
    db: PgPool,
    crypto: Arc<Crypto>,
}
impl PgGrantStore {
    pub fn new(db: PgPool, crypto: Arc<Crypto>) -> Self {
        Self { db, crypto }
    }
}
fn dependency(_: sqlx::Error) -> Error {
    Error::Dependency
}
struct PgGrantTransaction {
    tx: Transaction<'static, Postgres>,
    crypto: Arc<Crypto>,
}

#[async_trait]
impl GrantStore for PgGrantStore {
    async fn client(&self, id: &str) -> Result<Option<Client>> {
        let row = sqlx::query("SELECT client_id,client_secret_hash,redirect_uris,allowed_scopes,is_public FROM oauth_clients WHERE client_id=$1")
            .bind(id).fetch_optional(&self.db).await.map_err(dependency)?;
        row.map(|row| {
            Ok(Client {
                client_id: row.try_get("client_id").map_err(dependency)?,
                secret_hash: row.try_get("client_secret_hash").map_err(dependency)?,
                redirect_uris: row.try_get("redirect_uris").map_err(dependency)?,
                allowed_scopes: row.try_get("allowed_scopes").map_err(dependency)?,
                is_public: row.try_get("is_public").map_err(dependency)?,
            })
        })
        .transpose()
    }
    async fn create_code(&self, code: &NewCode) -> Result<bool> {
        let changed = sqlx::query("INSERT INTO oauth_authorization_codes(code_hash,client_id,session_id,user_id,redirect_uri,scope,nonce,code_challenge,expires_at) SELECT $1,$2,s.id,s.user_id,$5,$6,$7,$8,LEAST($9,s.expires_at) FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$3 AND s.user_id=$4 AND s.is_active AND s.expires_at>NOW() AND NOT u.is_banned")
            .bind(&code.hash).bind(&code.client_id).bind(code.subject.session_id).bind(code.subject.user_id)
            .bind(&code.redirect_uri).bind(&code.scope).bind(&code.nonce).bind(&code.challenge).bind(code.expires_at)
            .execute(&self.db).await.map_err(dependency)?;
        Ok(changed.rows_affected() == 1)
    }
    async fn begin(&self) -> Result<Box<dyn GrantTransaction>> {
        Ok(Box::new(PgGrantTransaction {
            tx: self.db.begin().await.map_err(dependency)?,
            crypto: self.crypto.clone(),
        }))
    }
}

#[async_trait]
impl GrantTransaction for PgGrantTransaction {
    async fn code_subject(&mut self, hash: &str) -> Result<Option<Subject>> {
        let row = sqlx::query(
            "SELECT user_id,session_id FROM oauth_authorization_codes WHERE code_hash=$1",
        )
        .bind(hash)
        .fetch_optional(&mut *self.tx)
        .await
        .map_err(dependency)?;
        row.map(|row| {
            Ok(Subject {
                user_id: row.try_get("user_id").map_err(dependency)?,
                session_id: row.try_get("session_id").map_err(dependency)?,
            })
        })
        .transpose()
    }
    async fn refresh_identity(&mut self, hash: &str) -> Result<Option<RefreshIdentity>> {
        let row = sqlx::query("SELECT f.id,f.client_id,f.user_id,f.session_id FROM oauth_refresh_tokens r JOIN oauth_token_families f ON f.id=r.family_id WHERE r.token_hash=$1")
            .bind(hash).fetch_optional(&mut *self.tx).await.map_err(dependency)?;
        row.map(|row| {
            Ok(RefreshIdentity {
                family_id: row.try_get("id").map_err(dependency)?,
                client_id: row.try_get("client_id").map_err(dependency)?,
                subject: Subject {
                    user_id: row.try_get("user_id").map_err(dependency)?,
                    session_id: row.try_get("session_id").map_err(dependency)?,
                },
            })
        })
        .transpose()
    }
    async fn lock_session(&mut self, subject: Subject) -> Result<Option<LiveSession>> {
        // Global mutation order: user -> session -> code/family -> refresh.
        let user =
            sqlx::query("SELECT email,is_verified,is_banned FROM users WHERE id=$1 FOR UPDATE")
                .bind(subject.user_id)
                .fetch_optional(&mut *self.tx)
                .await
                .map_err(dependency)?;
        let Some(user) = user else { return Ok(None) };
        if user.try_get::<bool, _>("is_banned").map_err(dependency)? {
            return Ok(None);
        }
        let row = sqlx::query("SELECT expires_at FROM sessions WHERE id=$1 AND user_id=$2 AND is_active AND expires_at>NOW() FOR UPDATE")
            .bind(subject.session_id).bind(subject.user_id).fetch_optional(&mut *self.tx).await.map_err(dependency)?;
        match row {
            Some(row) => Ok(Some(LiveSession {
                subject,
                email: user.try_get("email").map_err(dependency)?,
                email_verified: user.try_get("is_verified").map_err(dependency)?,
                expires_at: row.try_get("expires_at").map_err(dependency)?,
            })),
            None => Ok(None),
        }
    }
    async fn lock_code(&mut self, hash: &str) -> Result<Option<Code>> {
        let row = sqlx::query("SELECT client_id,session_id,user_id,redirect_uri,scope,nonce,code_challenge,expires_at,consumed_at,family_id FROM oauth_authorization_codes WHERE code_hash=$1 FOR UPDATE")
            .bind(hash).fetch_optional(&mut *self.tx).await.map_err(dependency)?;
        row.map(|row| {
            Ok(Code {
                client_id: row.try_get("client_id").map_err(dependency)?,
                subject: Subject {
                    user_id: row.try_get("user_id").map_err(dependency)?,
                    session_id: row.try_get("session_id").map_err(dependency)?,
                },
                redirect_uri: row.try_get("redirect_uri").map_err(dependency)?,
                scope: row.try_get("scope").map_err(dependency)?,
                nonce: row.try_get("nonce").map_err(dependency)?,
                challenge: row.try_get("code_challenge").map_err(dependency)?,
                expires_at: row.try_get("expires_at").map_err(dependency)?,
                consumed: row
                    .try_get::<Option<DateTime<Utc>>, _>("consumed_at")
                    .map_err(dependency)?
                    .is_some(),
                family_id: row.try_get("family_id").map_err(dependency)?,
            })
        })
        .transpose()
    }
    async fn lock_refresh(&mut self, hash: &str, family_id: Uuid) -> Result<Refresh> {
        let family = sqlx::query("SELECT client_id,user_id,session_id,scope,nonce,expires_at,revoked_at FROM oauth_token_families WHERE id=$1 FOR UPDATE")
            .bind(family_id).fetch_one(&mut *self.tx).await.map_err(dependency)?;
        let token = sqlx::query("SELECT expires_at,consumed_at FROM oauth_refresh_tokens WHERE token_hash=$1 AND family_id=$2 FOR UPDATE")
            .bind(hash).bind(family_id).fetch_one(&mut *self.tx).await.map_err(dependency)?;
        Ok(Refresh {
            family: Family {
                id: family_id,
                client_id: family.try_get("client_id").map_err(dependency)?,
                subject: Subject {
                    user_id: family.try_get("user_id").map_err(dependency)?,
                    session_id: family.try_get("session_id").map_err(dependency)?,
                },
                scope: family.try_get("scope").map_err(dependency)?,
                nonce: family.try_get("nonce").map_err(dependency)?,
                expires_at: family.try_get("expires_at").map_err(dependency)?,
                revoked: family
                    .try_get::<Option<DateTime<Utc>>, _>("revoked_at")
                    .map_err(dependency)?
                    .is_some(),
            },
            expires_at: token.try_get("expires_at").map_err(dependency)?,
            consumed: token
                .try_get::<Option<DateTime<Utc>>, _>("consumed_at")
                .map_err(dependency)?
                .is_some(),
        })
    }
    async fn grant_code(
        &mut self,
        hash: &str,
        family: &Family,
        refresh_hash: Option<&str>,
    ) -> Result<()> {
        sqlx::query("INSERT INTO oauth_token_families(id,client_id,session_id,user_id,scope,nonce,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(family.id).bind(&family.client_id).bind(family.subject.session_id).bind(family.subject.user_id).bind(&family.scope).bind(&family.nonce).bind(family.expires_at)
            .execute(&mut *self.tx).await.map_err(dependency)?;
        if let Some(refresh_hash) = refresh_hash {
            sqlx::query("INSERT INTO oauth_refresh_tokens(token_hash,family_id,expires_at) VALUES($1,$2,$3)")
                .bind(refresh_hash).bind(family.id).bind(family.expires_at).execute(&mut *self.tx).await.map_err(dependency)?;
        }
        sqlx::query("UPDATE oauth_authorization_codes SET consumed_at=NOW(),family_id=$2 WHERE code_hash=$1")
            .bind(hash).bind(family.id).execute(&mut *self.tx).await.map_err(dependency)?;
        Ok(())
    }
    async fn rotate(&mut self, old_hash: &str, new_hash: &str, family: &Family) -> Result<()> {
        sqlx::query("UPDATE oauth_token_families SET scope=$2 WHERE id=$1")
            .bind(family.id)
            .bind(&family.scope)
            .execute(&mut *self.tx)
            .await
            .map_err(dependency)?;
        sqlx::query("UPDATE oauth_refresh_tokens SET consumed_at=NOW() WHERE token_hash=$1")
            .bind(old_hash)
            .execute(&mut *self.tx)
            .await
            .map_err(dependency)?;
        sqlx::query(
            "INSERT INTO oauth_refresh_tokens(token_hash,family_id,expires_at) VALUES($1,$2,$3)",
        )
        .bind(new_hash)
        .bind(family.id)
        .bind(family.expires_at)
        .execute(&mut *self.tx)
        .await
        .map_err(dependency)?;
        Ok(())
    }
    async fn revoke_replay(
        &mut self,
        subject: Subject,
        family_id: Uuid,
        reason: &'static str,
    ) -> Result<()> {
        sqlx::query("UPDATE oauth_token_families SET revoked_at=COALESCE(revoked_at,NOW()),revoked_reason=$2 WHERE id=$1")
            .bind(family_id).bind(reason).execute(&mut *self.tx).await.map_err(dependency)?;
        let user: Option<Uuid> = sqlx::query_scalar("UPDATE sessions SET is_active=false,revoked_reason=$2 WHERE id=$1 AND is_active RETURNING user_id")
            .bind(subject.session_id).bind(reason).fetch_optional(&mut *self.tx).await.map_err(dependency)?;
        if let Some(user_id) = user {
            crate::events::enqueue(
                &mut self.tx,
                &self.crypto,
                "identity.session_revoked",
                user_id,
                json!({"user_id":user_id,"session_id":subject.session_id,"reason":reason}),
                None,
            )
            .await
            .map_err(|_| Error::Dependency)?;
        }
        Ok(())
    }
    async fn commit(self: Box<Self>) -> Result<()> {
        let Self { tx, .. } = *self;
        tx.commit().await.map_err(dependency)
    }
}
