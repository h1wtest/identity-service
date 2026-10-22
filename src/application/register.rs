use std::sync::Arc;
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::entities::{OutboxEvent, User};
use crate::domain::errors::AuthError;
use crate::domain::ports::{CryptoService, OutboxRepository, RbacRepository, UserRepository};

#[derive(Debug, Deserialize)]
pub struct RegisterCommand {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResult {
    pub user_id: Uuid,
    pub email: String,
    pub message: String,
}

pub struct RegisterUseCase {
    user_repo: Arc<dyn UserRepository>,
    rbac_repo: Arc<dyn RbacRepository>,
    outbox_repo: Arc<dyn OutboxRepository>,
    crypto: Arc<dyn CryptoService>,
}

impl RegisterUseCase {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        rbac_repo: Arc<dyn RbacRepository>,
        outbox_repo: Arc<dyn OutboxRepository>,
        crypto: Arc<dyn CryptoService>,
    ) -> Self {
        Self {
            user_repo,
            rbac_repo,
            outbox_repo,
            crypto,
        }
    }

    pub async fn execute(&self, cmd: RegisterCommand) -> Result<RegisterResult, AuthError> {
        let email = cmd.email.trim().to_lowercase();
        if email.is_empty() || !email.contains('@') {
            return Err(AuthError::Internal("Invalid email address".to_string()));
        }

        if cmd.password.len() < 8 {
            return Err(AuthError::Internal("Password must be at least 8 characters long".to_string()));
        }

        if self.user_repo.find_by_email(&email).await?.is_some() {
            return Err(AuthError::UserAlreadyExists(email));
        }

        let password_hash = self.crypto.hash_password(&cmd.password)?;
        let user_id = Uuid::now_v7();
        let now = Utc::now();

        let user = User {
            id: user_id,
            email: email.clone(),
            password_hash,
            is_verified: false,
            is_banned: false,
            ban_reason: None,
            created_at: now,
            updated_at: now,
        };

        // 1. Create User
        self.user_repo.create_user(&user).await?;

        // 2. Assign default role "user"
        self.rbac_repo.assign_role(user_id, "user").await?;

        // 3. Generate verification code (6 digits)
        let verification_code: u32 = rand::thread_rng().gen_range(100_000..999_999);

        // 4. Record UserRegisteredEvent into Transactional Outbox
        let event_payload = serde_json::json!({
            "event_id": Uuid::now_v7().to_string(),
            "event_type": "auth.user_registered",
            "timestamp": now.to_rfc3339(),
            "producer": "identity-service",
            "user_registered": {
                "user_id": user_id.to_string(),
                "email": email.clone(),
                "verification_code": verification_code.to_string(),
                "expires_at": (now + chrono::Duration::hours(24)).to_rfc3339(),
            }
        });

        let outbox_event = OutboxEvent {
            id: Uuid::now_v7(),
            event_type: "auth.user_registered".to_string(),
            aggregate_id: user_id.to_string(),
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

        Ok(RegisterResult {
            user_id,
            email,
            message: "User registered successfully. Check email for verification code.".to_string(),
        })
    }
}
