use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::domain::entities::User;
use crate::domain::errors::AuthError;
use crate::domain::ports::UserRepository;

#[derive(Clone)]
pub struct PostgresUserRepository {
    pool: PgPool,
}

impl PostgresUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn create_user(&self, user: &User) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            INSERT INTO users (id, email, password_hash, is_verified, is_banned, ban_reason, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(user.id)
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(user.is_verified)
        .bind(user.is_banned)
        .bind(&user.ban_reason)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if let Some(db_err) = e.as_database_error() {
                if db_err.is_unique_violation() {
                    return AuthError::UserAlreadyExists(user.email.clone());
                }
            }
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(())
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT id, email, password_hash, is_verified, is_banned, ban_reason, created_at, updated_at
            FROM users
            WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        let user = row.map(|r| User {
            id: r.get("id"),
            email: r.get("email"),
            password_hash: r.get("password_hash"),
            is_verified: r.get("is_verified"),
            is_banned: r.get("is_banned"),
            ban_reason: r.get("ban_reason"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        });

        Ok(user)
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT id, email, password_hash, is_verified, is_banned, ban_reason, created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        let user = row.map(|r| User {
            id: r.get("id"),
            email: r.get("email"),
            password_hash: r.get("password_hash"),
            is_verified: r.get("is_verified"),
            is_banned: r.get("is_banned"),
            ban_reason: r.get("ban_reason"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        });

        Ok(user)
    }

    async fn set_banned(&self, id: Uuid, is_banned: bool, reason: Option<&str>) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE users
            SET is_banned = $1, ban_reason = $2, updated_at = NOW()
            WHERE id = $3
            "#,
        )
        .bind(is_banned)
        .bind(reason)
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn set_verified(&self, id: Uuid, is_verified: bool) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE users
            SET is_verified = $1, updated_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(is_verified)
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
