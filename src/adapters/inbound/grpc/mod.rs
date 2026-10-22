use std::sync::Arc;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::application::sessions::SessionsUseCase;
use crate::domain::ports::{CryptoService, RbacRepository, SessionStore, UserRepository};
use crate::proto::identity::v1::identity_service_server::IdentityService;
use crate::proto::identity::v1::{
    BanUserRequest, BanUserResponse, CheckPermissionRequest, CheckPermissionResponse,
    GetUserSessionsRequest, GetUserSessionsResponse, RevokeAllSessionsRequest,
    RevokeAllSessionsResponse, RevokeSessionRequest, RevokeSessionResponse, SessionItem,
    ValidateTokenRequest, ValidateTokenResponse,
};

pub struct GrpcIdentityService {
    user_repo: Arc<dyn UserRepository>,
    rbac_repo: Arc<dyn RbacRepository>,
    session_store: Arc<dyn SessionStore>,
    sessions_use_case: Arc<SessionsUseCase>,
    crypto: Arc<dyn CryptoService>,
}

impl GrpcIdentityService {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        rbac_repo: Arc<dyn RbacRepository>,
        session_store: Arc<dyn SessionStore>,
        sessions_use_case: Arc<SessionsUseCase>,
        crypto: Arc<dyn CryptoService>,
    ) -> Self {
        Self {
            user_repo,
            rbac_repo,
            session_store,
            sessions_use_case,
            crypto,
        }
    }
}

#[tonic::async_trait]
impl IdentityService for GrpcIdentityService {
    async fn validate_token(
        &self,
        request: Request<ValidateTokenRequest>,
    ) -> Result<Response<ValidateTokenResponse>, Status> {
        let req = request.into_inner();
        let claims = match self.crypto.verify_access_token(&req.access_token) {
            Ok(c) => c,
            Err(e) => {
                return Ok(Response::new(ValidateTokenResponse {
                    is_valid: false,
                    error_message: e.to_string(),
                    ..Default::default()
                }));
            }
        };

        // Check if session is alive in Redis
        let session_alive = match self.session_store.get_session(&claims.sid).await {
            Ok(Some(_)) => true,
            _ => false,
        };

        if !session_alive {
            return Ok(Response::new(ValidateTokenResponse {
                is_valid: false,
                error_message: "Session has been revoked or expired".to_string(),
                ..Default::default()
            }));
        }

        let user_id = match Uuid::parse_str(&claims.sub) {
            Ok(id) => id,
            Err(_) => {
                return Ok(Response::new(ValidateTokenResponse {
                    is_valid: false,
                    error_message: "Invalid user ID claim".to_string(),
                    ..Default::default()
                }));
            }
        };

        // Check if user is banned
        if let Ok(Some(user)) = self.user_repo.find_by_id(user_id).await {
            if user.is_banned {
                return Ok(Response::new(ValidateTokenResponse {
                    is_valid: false,
                    error_message: format!(
                        "Account is suspended: {}",
                        user.ban_reason.unwrap_or_default()
                    ),
                    ..Default::default()
                }));
            }
        }

        let expires_at = prost_types::Timestamp {
            seconds: claims.exp,
            nanos: 0,
        };

        Ok(Response::new(ValidateTokenResponse {
            is_valid: true,
            user_id: claims.sub,
            session_id: claims.sid,
            roles: claims.roles,
            permissions: claims.permissions,
            expires_at: Some(expires_at),
            error_message: String::new(),
        }))
    }

    async fn check_permission(
        &self,
        request: Request<CheckPermissionRequest>,
    ) -> Result<Response<CheckPermissionResponse>, Status> {
        let req = request.into_inner();
        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("Invalid user_id UUID"))?;

        match self.rbac_repo.check_permission(user_id, &req.permission).await {
            Ok(allowed) => Ok(Response::new(CheckPermissionResponse {
                allowed,
                reason: if allowed {
                    "Permission granted".to_string()
                } else {
                    format!("Missing permission: {}", req.permission)
                },
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn get_user_sessions(
        &self,
        request: Request<GetUserSessionsRequest>,
    ) -> Result<Response<GetUserSessionsResponse>, Status> {
        let req = request.into_inner();
        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("Invalid user_id UUID"))?;

        let current_sid = if req.current_session_id.is_empty() {
            None
        } else {
            Uuid::parse_str(&req.current_session_id).ok()
        };

        let sessions = self
            .sessions_use_case
            .list_sessions(user_id, current_sid)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let proto_sessions = sessions
            .into_iter()
            .map(|s| SessionItem {
                session_id: s.session_id.to_string(),
                ip_address: s.ip_address,
                user_agent: s.user_agent,
                device_name: s.device_name.unwrap_or_default(),
                location: s.location.unwrap_or_default(),
                is_current: s.is_current,
                created_at: None,
                last_active_at: None,
            })
            .collect();

        Ok(Response::new(GetUserSessionsResponse {
            sessions: proto_sessions,
        }))
    }

    async fn revoke_session(
        &self,
        request: Request<RevokeSessionRequest>,
    ) -> Result<Response<RevokeSessionResponse>, Status> {
        let req = request.into_inner();
        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("Invalid user_id UUID"))?;
        let session_id = Uuid::parse_str(&req.session_id)
            .map_err(|_| Status::invalid_argument("Invalid session_id UUID"))?;

        let reason = if req.reason.is_empty() {
            "revoked_via_grpc"
        } else {
            &req.reason
        };

        self.sessions_use_case
            .revoke_session(user_id, session_id, reason)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RevokeSessionResponse { success: true }))
    }

    async fn revoke_all_sessions(
        &self,
        request: Request<RevokeAllSessionsRequest>,
    ) -> Result<Response<RevokeAllSessionsResponse>, Status> {
        let req = request.into_inner();
        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("Invalid user_id UUID"))?;

        let reason = if req.reason.is_empty() {
            "all_sessions_revoked_via_grpc"
        } else {
            &req.reason
        };

        let count = self
            .sessions_use_case
            .revoke_all_sessions(user_id, reason)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RevokeAllSessionsResponse {
            success: true,
            revoked_count: count,
        }))
    }

    async fn ban_user(
        &self,
        request: Request<BanUserRequest>,
    ) -> Result<Response<BanUserResponse>, Status> {
        let req = request.into_inner();
        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("Invalid user_id UUID"))?;

        let reason = if req.reason.is_empty() {
            "Banned by administrator"
        } else {
            &req.reason
        };

        // 1. Mark user banned in DB
        self.user_repo
            .set_banned(user_id, true, Some(reason))
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // 2. Revoke all active sessions
        self.sessions_use_case
            .revoke_all_sessions(user_id, "admin_ban")
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(BanUserResponse { success: true }))
    }
}
