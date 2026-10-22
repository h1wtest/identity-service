use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::domain::errors::AuthError;
use crate::domain::ports::RbacRepository;

#[derive(Clone)]
pub struct PostgresRbacRepository {
    pool: PgPool,
}

impl PostgresRbacRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RbacRepository for PostgresRbacRepository {
    async fn get_user_roles(&self, user_id: Uuid) -> Result<Vec<String>, AuthError> {
        let rows = sqlx::query(
            r#"
            SELECT r.slug
            FROM roles r
            JOIN user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = $1
              AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
            ORDER BY r.slug
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let roles = rows.into_iter().map(|r| r.get("slug")).collect();
        Ok(roles)
    }

    async fn get_user_permissions(&self, user_id: Uuid) -> Result<Vec<String>, AuthError> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT p.slug
            FROM permissions p
            JOIN role_permissions rp ON rp.permission_id = p.id
            JOIN roles r ON r.id = rp.role_id
            JOIN user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = $1
              AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
            ORDER BY p.slug
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let permissions = rows.into_iter().map(|r| r.get("slug")).collect();
        Ok(permissions)
    }

    async fn assign_role(&self, user_id: Uuid, role_slug: &str) -> Result<(), AuthError> {
        let role_row = sqlx::query("SELECT id FROM roles WHERE slug = $1")
            .bind(role_slug)
            .fetch_optional(&self.pool)
            .await?;

        let role_id: Uuid = match role_row {
            Some(r) => r.get("id"),
            None => return Err(AuthError::Internal(format!("Role '{}' does not exist", role_slug))),
        };

        sqlx::query(
            r#"
            INSERT INTO user_roles (user_id, role_id, created_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (user_id, role_id) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(role_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn check_permission(&self, user_id: Uuid, permission: &str) -> Result<bool, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT 1
            FROM permissions p
            JOIN role_permissions rp ON rp.permission_id = p.id
            JOIN roles r ON r.id = rp.role_id
            JOIN user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = $1
              AND p.slug = $2
              AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .bind(permission)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.is_some())
    }
}
