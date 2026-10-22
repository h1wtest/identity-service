use std::sync::Arc;
use chrono::Utc;
use rand::distributions::Alphanumeric;
use rand::Rng;
use uuid::Uuid;

use crate::adapters::outbound::crypto::DefaultCryptoService;
use crate::domain::entities::{
    OAuthAuthorizationCode, OAuthTokenResponse, RedisSessionData, Session,
};
use crate::domain::errors::AuthError;
use crate::domain::ports::{
    CryptoService, OAuthClientRepository, OAuthCodeStore, RbacRepository,
    SessionMetadataRepository, SessionStore, UserRepository,
};

pub struct OAuthUseCase {
    client_repo: Arc<dyn OAuthClientRepository>,
    code_store: Arc<dyn OAuthCodeStore>,
    user_repo: Arc<dyn UserRepository>,
    rbac_repo: Arc<dyn RbacRepository>,
    session_store: Arc<dyn SessionStore>,
    session_metadata_repo: Arc<dyn SessionMetadataRepository>,
    crypto: Arc<dyn CryptoService>,
    issuer: String,
    refresh_ttl: i64,
}

impl OAuthUseCase {
    pub fn new(
        client_repo: Arc<dyn OAuthClientRepository>,
        code_store: Arc<dyn OAuthCodeStore>,
        user_repo: Arc<dyn UserRepository>,
        rbac_repo: Arc<dyn RbacRepository>,
        session_store: Arc<dyn SessionStore>,
        session_metadata_repo: Arc<dyn SessionMetadataRepository>,
        crypto: Arc<dyn CryptoService>,
        issuer: String,
        refresh_ttl: i64,
    ) -> Self {
        Self {
            client_repo,
            code_store,
            user_repo,
            rbac_repo,
            session_store,
            session_metadata_repo,
            crypto,
            issuer,
            refresh_ttl,
        }
    }

    pub async fn authorize(
        &self,
        user_id: Uuid,
        client_id: &str,
        redirect_uri: &str,
        response_type: &str,
        scope: &str,
        code_challenge: &str,
        code_challenge_method: &str,
        state: Option<&str>,
    ) -> Result<String, AuthError> {
        // 1. Validate response_type (OAuth 2.1 strictly requires "code")
        if response_type != "code" {
            return Err(AuthError::Internal(
                "Unsupported response_type. Only 'code' is allowed in OAuth 2.1".to_string(),
            ));
        }

        // 2. Validate PKCE S256 (OAuth 2.1 mandates PKCE S256)
        if code_challenge.is_empty() || code_challenge_method != "S256" {
            return Err(AuthError::Internal(
                "OAuth 2.1 mandates PKCE with code_challenge_method=S256".to_string(),
            ));
        }

        // 3. Validate client and redirect_uri
        let client = self
            .client_repo
            .find_client(client_id)
            .await?
            .ok_or_else(|| AuthError::Internal(format!("Invalid client_id: {}", client_id)))?;

        let uri_allowed = client.redirect_uris.iter().any(|u| u == redirect_uri);
        if !uri_allowed {
            return Err(AuthError::Internal(format!(
                "Redirect URI '{}' is not registered for client '{}'",
                redirect_uri, client_id
            )));
        }

        // 4. Generate cryptographically secure authorization code (32 chars)
        let code: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let now = Utc::now();
        let expires_at = now.timestamp() + 300; // 5 minutes TTL

        let auth_code = OAuthAuthorizationCode {
            code: code.clone(),
            client_id: client_id.to_string(),
            user_id: user_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scope: scope.to_string(),
            code_challenge: code_challenge.to_string(),
            code_challenge_method: code_challenge_method.to_string(),
            expires_at,
        };

        // 5. Save code in Redis with 300s TTL
        self.code_store.save_code(&auth_code, 300).await?;

        // 6. Construct redirect URL
        let delimiter = if redirect_uri.contains('?') { "&" } else { "?" };
        let mut target = format!("{}{}code={}", redirect_uri, delimiter, code);
        if let Some(s) = state {
            target = format!("{}&state={}", target, s);
        }

        Ok(target)
    }

    pub async fn exchange_token(
        &self,
        client_id: &str,
        redirect_uri: &str,
        code: &str,
        code_verifier: &str,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<OAuthTokenResponse, AuthError> {
        // 1. Consume authorization code (atomic one-time read & delete)
        let auth_code = self
            .code_store
            .consume_code(code)
            .await?
            .ok_or_else(|| AuthError::Unauthorized("Invalid or expired authorization code".to_string()))?;

        // 2. Validate client and redirect_uri match the issue params
        if auth_code.client_id != client_id {
            return Err(AuthError::Unauthorized("client_id does not match authorization code".to_string()));
        }
        if auth_code.redirect_uri != redirect_uri {
            return Err(AuthError::Unauthorized("redirect_uri does not match authorization code".to_string()));
        }

        // 3. Verify PKCE S256
        let is_pkce_valid = DefaultCryptoService::verify_pkce(code_verifier, &auth_code.code_challenge);
        if !is_pkce_valid {
            return Err(AuthError::Unauthorized("Invalid PKCE code_verifier".to_string()));
        }

        // 4. Fetch User and Roles
        let user_id = Uuid::parse_str(&auth_code.user_id)
            .map_err(|_| AuthError::Internal("Invalid user ID in authorization code".to_string()))?;

        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        if user.is_banned {
            return Err(AuthError::AccountBanned(user.ban_reason.unwrap_or_default()));
        }

        let roles = self.rbac_repo.get_user_roles(user_id).await?;
        let permissions = self.rbac_repo.get_user_permissions(user_id).await?;

        // 5. Create Session in Redis & Postgres
        let session_id = Uuid::now_v7();
        let session_id_str = session_id.to_string();
        let user_id_str = user.id.to_string();

        let token_pair = self
            .crypto
            .generate_token_pair(&user_id_str, &session_id_str, &roles, &permissions)?;

        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(self.refresh_ttl);

        let redis_session = RedisSessionData {
            session_id: session_id_str.clone(),
            user_id: user_id_str.clone(),
            refresh_token_hash: DefaultCryptoService::hash_sha256(&token_pair.refresh_token),
            refresh_token_family: Uuid::now_v7().to_string(),
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            device_name: Some("OAuth Client".to_string()),
            location: None,
            created_at: now.timestamp(),
            last_active_at: now.timestamp(),
        };
        self.session_store
            .save_session(&redis_session, self.refresh_ttl as usize)
            .await?;

        let db_session = Session {
            id: session_id,
            user_id,
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            device_name: Some("OAuth Client".to_string()),
            location: None,
            is_active: true,
            revoked_reason: None,
            created_at: now,
            last_active_at: now,
            expires_at,
        };
        self.session_metadata_repo.record_session(&db_session).await?;

        // 6. Generate OIDC ID Token if openid scope is present
        let id_token = if auth_code.scope.contains("openid") {
            let idt = self.crypto.generate_id_token(
                &self.issuer,
                client_id,
                &user_id_str,
                &user.email,
                &roles,
                &permissions,
            )?;
            Some(idt)
        } else {
            None
        };

        Ok(OAuthTokenResponse {
            access_token: token_pair.access_token,
            token_type: "Bearer".to_string(),
            expires_in: token_pair.expires_in,
            refresh_token: Some(token_pair.refresh_token),
            id_token,
            scope: auth_code.scope,
        })
    }

    pub async fn get_userinfo(&self, user_id: Uuid) -> Result<serde_json::Value, AuthError> {
        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let roles = self.rbac_repo.get_user_roles(user_id).await?;
        let permissions = self.rbac_repo.get_user_permissions(user_id).await?;

        Ok(serde_json::json!({
            "sub": user.id.to_string(),
            "email": user.email,
            "email_verified": user.is_verified,
            "roles": roles,
            "permissions": permissions,
        }))
    }
}
