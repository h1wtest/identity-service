use std::sync::Arc;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::entities::{OutboxEvent, RedisSessionData, Session, TokenPair};
use crate::domain::errors::AuthError;
use crate::domain::ports::{
    CryptoService, MfaRepository, OutboxRepository, RbacRepository, SessionMetadataRepository,
    SessionStore, UserRepository,
};

#[derive(Debug, Deserialize)]
pub struct LoginCommand {
    pub email: String,
    pub password: String,
    pub ip_address: String,
    pub user_agent: String,
    pub device_name: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status")]
pub enum LoginResult {
    #[serde(rename = "authenticated")]
    Authenticated {
        tokens: TokenPair,
        session_id: Uuid,
    },
    #[serde(rename = "mfa_required")]
    MfaRequired {
        pre_auth_token: String,
        message: String,
    },
}

pub struct LoginUseCase {
    user_repo: Arc<dyn UserRepository>,
    rbac_repo: Arc<dyn RbacRepository>,
    mfa_repo: Arc<dyn MfaRepository>,
    session_store: Arc<dyn SessionStore>,
    session_metadata_repo: Arc<dyn SessionMetadataRepository>,
    outbox_repo: Arc<dyn OutboxRepository>,
    crypto: Arc<dyn CryptoService>,
    refresh_ttl: i64,
}

impl LoginUseCase {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        rbac_repo: Arc<dyn RbacRepository>,
        mfa_repo: Arc<dyn MfaRepository>,
        session_store: Arc<dyn SessionStore>,
        session_metadata_repo: Arc<dyn SessionMetadataRepository>,
        outbox_repo: Arc<dyn OutboxRepository>,
        crypto: Arc<dyn CryptoService>,
        refresh_ttl: i64,
    ) -> Self {
        Self {
            user_repo,
            rbac_repo,
            mfa_repo,
            session_store,
            session_metadata_repo,
            outbox_repo,
            crypto,
            refresh_ttl,
        }
    }

    pub async fn execute(&self, cmd: LoginCommand) -> Result<LoginResult, AuthError> {
        let email = cmd.email.trim().to_lowercase();
        let user = self
            .user_repo
            .find_by_email(&email)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        if user.is_banned {
            return Err(AuthError::AccountBanned(
                user.ban_reason.unwrap_or_else(|| "Account suspended".to_string()),
            ));
        }

        let is_password_valid = self
            .crypto
            .verify_password(&cmd.password, &user.password_hash)?;
        if !is_password_valid {
            return Err(AuthError::InvalidCredentials);
        }

        let session_id = Uuid::now_v7();
        let user_id_str = user.id.to_string();
        let session_id_str = session_id.to_string();

        // 1. Check if MFA is enabled
        let mfa_enabled = self.mfa_repo.is_mfa_enabled(user.id).await?;
        if mfa_enabled {
            let pre_auth_token = self
                .crypto
                .generate_pre_auth_token(&user_id_str, &session_id_str)?;
            return Ok(LoginResult::MfaRequired {
                pre_auth_token,
                message: "Please enter your TOTP 2FA code or a recovery code to complete login.".to_string(),
            });
        }

        // 2. MFA not enabled -> complete login directly
        let roles = self.rbac_repo.get_user_roles(user.id).await?;
        let permissions = self.rbac_repo.get_user_permissions(user.id).await?;

        let token_pair = self
            .crypto
            .generate_token_pair(&user_id_str, &session_id_str, &roles, &permissions)?;

        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(self.refresh_ttl);

        // Save session in Redis
        let redis_session = RedisSessionData {
            session_id: session_id_str.clone(),
            user_id: user_id_str.clone(),
            refresh_token_hash: crate::adapters::outbound::crypto::DefaultCryptoService::hash_sha256(&token_pair.refresh_token),
            refresh_token_family: Uuid::now_v7().to_string(),
            ip_address: cmd.ip_address.clone(),
            user_agent: cmd.user_agent.clone(),
            device_name: cmd.device_name.clone(),
            location: cmd.location.clone(),
            created_at: now.timestamp(),
            last_active_at: now.timestamp(),
        };
        self.session_store
            .save_session(&redis_session, self.refresh_ttl as usize)
            .await?;

        // Save session metadata in Postgres
        let db_session = Session {
            id: session_id,
            user_id: user.id,
            ip_address: cmd.ip_address.clone(),
            user_agent: cmd.user_agent.clone(),
            device_name: cmd.device_name.clone(),
            location: cmd.location.clone(),
            is_active: true,
            revoked_reason: None,
            created_at: now,
            last_active_at: now,
            expires_at,
        };
        self.session_metadata_repo.record_session(&db_session).await?;

        // Record UserLoggedInEvent into Transactional Outbox
        let event_payload = serde_json::json!({
            "event_id": Uuid::now_v7().to_string(),
            "event_type": "auth.user_logged_in",
            "timestamp": now.to_rfc3339(),
            "producer": "identity-service",
            "user_logged_in": {
                "user_id": user_id_str,
                "session_id": session_id_str,
                "ip_address": cmd.ip_address,
                "user_agent": cmd.user_agent,
                "device_name": cmd.device_name.unwrap_or_default(),
                "location": cmd.location.unwrap_or_default(),
                "is_new_device": false,
                "is_suspicious": false,
                "logged_in_at": now.to_rfc3339(),
            }
        });

        let outbox_event = OutboxEvent {
            id: Uuid::now_v7(),
            event_type: "auth.user_logged_in".to_string(),
            aggregate_id: user.id.to_string(),
            payload: event_payload,
            headers: serde_json::json!({
                "trace_id": Uuid::now_v7().to_string(),
            }),
            is_processed: false,
            retry_count: 0,
            last_error: None,
            created_at: now,
        };
        self.outbox_repo.save_event(&outbox_event).await?;

        Ok(LoginResult::Authenticated {
            tokens: token_pair,
            session_id,
        })
    }
}
