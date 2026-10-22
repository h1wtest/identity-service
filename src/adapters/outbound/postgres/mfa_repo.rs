use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::domain::errors::AuthError;
use crate::domain::ports::MfaRepository;

#[derive(Clone)]
pub struct PostgresMfaRepository {
    pool: PgPool,
}

impl PostgresMfaRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl MfaRepository for PostgresMfaRepository {
    async fn save_secret(&self, user_id: Uuid, secret: &str) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            INSERT INTO mfa_secrets (user_id, secret_key, is_enabled, created_at, updated_at)
            VALUES ($1, $2, FALSE, NOW(), NOW())
            ON CONFLICT (user_id) DO UPDATE SET
                secret_key = EXCLUDED.secret_key,
                is_enabled = FALSE,
                updated_at = NOW()
            "#,
        )
        .bind(user_id)
        .bind(secret)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_secret(&self, user_id: Uuid) -> Result<Option<String>, AuthError> {
        let row = sqlx::query("SELECT secret_key FROM mfa_secrets WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.map(|r| r.get("secret_key")))
    }

    async fn enable_mfa(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE mfa_secrets
            SET is_enabled = TRUE, updated_at = NOW()
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn disable_mfa(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE mfa_secrets
            SET is_enabled = FALSE, updated_at = NOW()
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn is_mfa_enabled(&self, user_id: Uuid) -> Result<bool, AuthError> {
        let row = sqlx::query("SELECT is_enabled FROM mfa_secrets WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.map(|r| r.get::<bool, _>("is_enabled")).unwrap_or(false))
    }

    async fn save_recovery_codes(&self, user_id: Uuid, hashes: &[String]) -> Result<(), AuthError> {
        // Clear previous unused codes
        sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1 AND is_used = FALSE")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        for hash in hashes {
            let code_id = Uuid::now_v7();
            sqlx::query(
                r#"
                INSERT INTO recovery_codes (id, user_id, code_hash, is_used, created_at)
                VALUES ($1, $2, $3, FALSE, NOW())
                "#,
            )
            .bind(code_id)
            .bind(user_id)
            .bind(hash)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    async fn consume_recovery_code(&self, user_id: Uuid, hash: &str) -> Result<bool, AuthError> {
        let res = sqlx::query(
            r#"
            UPDATE recovery_codes
            SET is_used = TRUE, used_at = NOW()
            WHERE user_id = $1 AND code_hash = $2 AND is_used = FALSE
            "#,
        )
        .bind(user_id)
        .bind(hash)
        .execute(&self.pool)
        .await?;

        Ok(res.rows_affected() > 0)
    }
}
