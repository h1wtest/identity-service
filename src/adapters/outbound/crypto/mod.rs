use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString},
    Argon2,
};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::domain::entities::{AccessTokenClaims, PreAuthTokenClaims, TokenPair};
use crate::domain::errors::AuthError;
use crate::domain::ports::CryptoService;

#[derive(Clone)]
pub struct DefaultCryptoService {
    jwt_secret: String,
    access_token_ttl: i64,
    refresh_token_ttl: i64,
}

impl DefaultCryptoService {
    pub fn new(jwt_secret: String, access_token_ttl: i64, refresh_token_ttl: i64) -> Self {
        Self {
            jwt_secret,
            access_token_ttl,
            refresh_token_ttl,
        }
    }

    pub fn hash_sha256(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn generate_totp_secret() -> String {
        let secret = Secret::generate_secret();
        secret.to_encoded().to_string()
    }

    pub fn verify_totp(secret_base32: &str, code: &str, email: &str) -> Result<bool, AuthError> {
        let secret = Secret::Encoded(secret_base32.to_string());
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_bytes().map_err(|e| AuthError::Internal(e.to_string()))?,
            Some("OurSSO".to_string()),
            email.to_string(),
        )
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(totp.check_current(code).unwrap_or(false))
    }

    pub fn generate_totp_qr_url(secret_base32: &str, email: &str) -> Result<String, AuthError> {
        let secret = Secret::Encoded(secret_base32.to_string());
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_bytes().map_err(|e| AuthError::Internal(e.to_string()))?,
            Some("OurSSO".to_string()),
            email.to_string(),
        )
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(totp.get_url())
    }
}

impl CryptoService for DefaultCryptoService {
    fn hash_password(&self, password: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::Internal(format!("Argon2 hashing failed: {}", e)))?
            .to_string();

        Ok(hash)
    }

    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, AuthError> {
        let parsed_hash = match PasswordHash::new(hash) {
            Ok(h) => h,
            Err(_) => return Ok(false),
        };

        let argon2 = Argon2::default();
        Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }

    fn generate_token_pair(
        &self,
        user_id: &str,
        session_id: &str,
        roles: &[String],
        permissions: &[String],
    ) -> Result<TokenPair, AuthError> {
        let now = Utc::now().timestamp();
        let exp = now + self.access_token_ttl;

        let access_claims = AccessTokenClaims {
            sub: user_id.to_string(),
            sid: session_id.to_string(),
            roles: roles.to_vec(),
            permissions: permissions.to_vec(),
            exp,
            iat: now,
        };

        let access_token = encode(
            &Header::default(),
            &access_claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|e| AuthError::Internal(format!("Failed to sign access token: {}", e)))?;

        // Cryptographically secure random refresh token
        let refresh_token = format!("{}.{}", uuid::Uuid::now_v7(), uuid::Uuid::now_v7());

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: self.access_token_ttl,
            token_type: "Bearer".to_string(),
        })
    }

    fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims, AuthError> {
        let mut validation = Validation::default();
        validation.validate_exp = true;

        let token_data = decode::<AccessTokenClaims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }

    fn generate_pre_auth_token(&self, user_id: &str, session_id: &str) -> Result<String, AuthError> {
        let now = Utc::now().timestamp();
        let exp = now + 180; // 3 minutes TTL for MFA step

        let claims = PreAuthTokenClaims {
            sub: user_id.to_string(),
            session_id: session_id.to_string(),
            scope: "mfa_pending".to_string(),
            exp,
            iat: now,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|e| AuthError::Internal(format!("Failed to sign pre-auth token: {}", e)))
    }

    fn verify_pre_auth_token(&self, token: &str) -> Result<PreAuthTokenClaims, AuthError> {
        let mut validation = Validation::default();
        validation.validate_exp = true;

        let token_data = decode::<PreAuthTokenClaims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|_| AuthError::InvalidToken)?;

        if token_data.claims.scope != "mfa_pending" {
            return Err(AuthError::InvalidToken);
        }

        Ok(token_data.claims)
    }
}
