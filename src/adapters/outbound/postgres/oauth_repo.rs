use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::domain::entities::OAuthClient;
use crate::domain::errors::AuthError;
use crate::domain::ports::OAuthClientRepository;

#[derive(Clone)]
pub struct PostgresOAuthClientRepository {
    pool: PgPool,
}

impl PostgresOAuthClientRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OAuthClientRepository for PostgresOAuthClientRepository {
    async fn find_client(&self, client_id: &str) -> Result<Option<OAuthClient>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT client_id, client_secret_hash, client_name, redirect_uris, allowed_scopes, is_public
            FROM oauth_clients
            WHERE client_id = $1
            "#,
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;

        let client = row.map(|r| OAuthClient {
            client_id: r.get("client_id"),
            client_secret_hash: r.get("client_secret_hash"),
            client_name: r.get("client_name"),
            redirect_uris: r.get("redirect_uris"),
            allowed_scopes: r.get("allowed_scopes"),
            is_public: r.get("is_public"),
        });

        Ok(client)
    }
}
