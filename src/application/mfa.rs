use std::sync::Arc;
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::adapters::outbound::crypto::DefaultCryptoService;
use crate::domain::entities::{OutboxEvent, RedisSessionData, Session, TokenPair};
use crate::domain::errors::AuthError;
use crate::domain::ports::{
    CryptoService, MfaRepository, OutboxRepository, RbacRepository, SessionMetadataRepository,
    SessionStore, UserRepository,
};

#[derive(Debug, Serialize)]
pub struct MfaSetupResponse {
    pub secret: String,
    pub qr_code_url: String,
    pub recovery_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyMfaLoginCommand {
    pub pre_auth_token: String,
    pub code: String, // 6 digits TOTP or 10-char recovery code
    pub ip_address: String,
    pub user_agent: String,
    pub device_name: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MfaLoginResponse {
    pub tokens: TokenPair,
    pub session_id: Uuid,
    pub used_recovery_code: bool,
}

pub struct MfaUseCase {
    user_repo: Arc<dyn UserRepository>,
    rbac_repo: Arc<dyn RbacRepository>,
    mfa_repo: Arc<dyn MfaRepository>,
    session_store: Arc<dyn SessionStore>,
    session_metadata_repo: Arc<dyn SessionMetadataRepository>,
    outbox_repo: Arc<dyn OutboxRepository>,
    crypto: Arc<dyn CryptoService>,
    refresh_ttl: i64,
}

impl MfaUseCase {
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

    pub async fn setup_mfa(&self, user_id: Uuid) -> Result<MfaSetupResponse, AuthError> {
        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let secret = DefaultCryptoService::generate_totp_secret();
        let qr_code_url = DefaultCryptoService::generate_totp_qr_url(&secret, &user.email)?;

        // Generate 10 random recovery codes (e.g. "ABCD-1234")
        let mut recovery_codes = Vec::with_capacity(10);
        let mut hashes = Vec::with_capacity(10);
        for _ in 0..10 {
            let code: String = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(10)
                .map(char::from)
                .collect();
            let upper_code = code.to_uppercase();
            let hash = DefaultCryptoService::hash_sha256(&upper_code);
            recovery_codes.push(upper_code);
            hashes.push(hash);
        }

        // Save unconfirmed secret and codes
        self.mfa_repo.save_secret(user_id, &secret).await?;
        self.mfa_repo.save_recovery_codes(user_id, &hashes).await?;

        Ok(MfaSetupResponse {
            secret,
            qr_code_url,
            recovery_codes,
        })
    }

    pub async fn enable_mfa(&self, user_id: Uuid, code: &str) -> Result<(), AuthError> {
        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let secret = self
            .mfa_repo
            .get_secret(user_id)
            .await?
            .ok_or(AuthError::MfaNotConfigured)?;

        let is_valid = DefaultCryptoService::verify_totp(&secret, code, &user.email)?;
        if !is_valid {
            return Err(AuthError::InvalidMfaCode);
        }

        self.mfa_repo.enable_mfa(user_id).await?;

        // Record MfaToggledEvent into Outbox
        let now = Utc::now();
        let event_payload = serde_json::json!({
            "event_id": Uuid::now_v7().to_string(),
            "event_type": "auth.mfa_toggled",
            "timestamp": now.to_rfc3339(),
            "producer": "identity-service",
            "mfa_toggled": {
                "user_id": user_id.to_string(),
                "enabled": true,
                "method": "totp",
                "toggled_at": now.to_rfc3339(),
            }
        });

        let outbox_event = OutboxEvent {
            id: Uuid::now_v7(),
            event_type: "auth.mfa_toggled".to_string(),
            aggregate_id: user_id.to_string(),
            payload: event_payload,
            headers: serde_json::json!({"trace_id": Uuid::now_v7().to_string()}),
            is_processed: false,
            retry_count: 0,
            last_error: None,
            created_at: now,
        };
        self.outbox_repo.save_event(&outbox_event).await?;

        Ok(())
    }

    pub async fn verify_login_mfa(
        &self,
        cmd: VerifyMfaLoginCommand,
    ) -> Result<MfaLoginResponse, AuthError> {
        let claims = self.crypto.verify_pre_auth_token(&cmd.pre_auth_token)?;
        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AuthError::InvalidToken)?;
        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let secret = self
            .mfa_repo
            .get_secret(user_id)
            .await?
            .ok_or(AuthError::MfaNotConfigured)?;

        let trimmed_code = cmd.code.trim();
        let mut used_recovery = false;

        // 1. Try TOTP check if 6 digits
        let mut valid = false;
        if trimmed_code.len() == 6 && trimmed_code.chars().all(|c| c.is_ascii_digit()) {
            valid = DefaultCryptoService::verify_totp(&secret, trimmed_code, &user.email)?;
        }

        // 2. If not valid TOTP, try recovery code
        if !valid {
            let code_hash = DefaultCryptoService::hash_sha256(&trimmed_code.to_uppercase());
            if self.mfa_repo.consume_recovery_code(user_id, &code_hash).await? {
                valid = true;
                used_recovery = true;
            }
        }

        if !valid {
            return Err(AuthError::InvalidMfaCode);
        }

        // 3. Authenticated: create session and issue tokens
        let session_id = Uuid::now_v7();
        let user_id_str = user.id.to_string();
        let session_id_str = session_id.to_string();

        let roles = self.rbac_repo.get_user_roles(user.id).await?;
        let permissions = self.rbac_repo.get_user_permissions(user.id).await?;

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
            headers: serde_json::json!({"trace_id": Uuid::now_v7().to_string()}),
            is_processed: false,
            retry_count: 0,
            last_error: None,
            created_at: now,
        };
        self.outbox_repo.save_event(&outbox_event).await?;

        Ok(MfaLoginResponse {
            tokens: token_pair,
            session_id,
            used_recovery_code: used_recovery,
        })
    }
}
