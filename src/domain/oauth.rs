use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;
use uuid::Uuid;

pub const SUPPORTED_SCOPES: &[&str] = &["openid", "email", "profile", "offline_access"];
pub const ACCESS_TTL_SECONDS: i64 = 300;
pub const CODE_TTL_SECONDS: i64 = 120;
pub const REFRESH_TTL_DAYS: i64 = 30;

#[derive(Debug, Clone, Copy)]
pub enum Error {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    InvalidScope,
    UnsupportedGrantType,
    UnsupportedResponseType,
    LoginRequired,
    InvalidToken,
    InsufficientScope,
    Dependency,
}
impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidScope => "invalid_scope",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::LoginRequired => "login_required",
            Self::InvalidToken => "invalid_token",
            Self::InsufficientScope => "insufficient_scope",
            Self::Dependency => "temporarily_unavailable",
        }
    }
}
pub type Result<T, E = Error> = std::result::Result<T, E>;

pub struct Client {
    pub client_id: String,
    pub secret_hash: Option<String>,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub is_public: bool,
}
impl Client {
    pub fn redirect(&self, requested: &str) -> Result<Url> {
        if !self
            .redirect_uris
            .iter()
            .any(|registered| registered == requested)
        {
            return Err(Error::InvalidRequest);
        }
        let uri = Url::parse(requested).map_err(|_| Error::InvalidRequest)?;
        if uri.scheme() != "https"
            || uri.host_str().is_none()
            || uri.fragment().is_some()
            || !uri.username().is_empty()
            || uri.password().is_some()
        {
            return Err(Error::InvalidRequest);
        }
        Ok(uri)
    }
    pub fn scope(&self, requested: &str) -> Result<String> {
        if requested.is_empty()
            || !requested.bytes().all(|b| {
                b == b' ' || b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b)
            })
        {
            return Err(Error::InvalidScope);
        }
        let scopes: Vec<_> = requested
            .split(' ')
            .filter(|part| !part.is_empty())
            .collect();
        if !scopes.contains(&"openid")
            || scopes.iter().any(|scope| {
                !SUPPORTED_SCOPES.contains(scope)
                    || !self
                        .allowed_scopes
                        .iter()
                        .any(|allowed| allowed.as_str() == *scope)
            })
        {
            return Err(Error::InvalidScope);
        }
        Ok(SUPPORTED_SCOPES
            .iter()
            .filter(|scope| scopes.contains(scope))
            .copied()
            .collect::<Vec<_>>()
            .join(" "))
    }
}
pub fn has_scope(scope: &str, expected: &str) -> bool {
    scope.split(' ').any(|part| part == expected)
}
pub fn validate_challenge(challenge: &str, method: &str) -> Result<()> {
    if method != "S256"
        || challenge.len() != 43
        || !URL_SAFE_NO_PAD
            .decode(challenge)
            .is_ok_and(|bytes| bytes.len() == 32)
    {
        return Err(Error::InvalidRequest);
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub struct Subject {
    pub user_id: Uuid,
    pub session_id: Uuid,
}
pub struct LiveSession {
    pub subject: Subject,
    pub email: String,
    pub email_verified: bool,
    pub expires_at: DateTime<Utc>,
}
pub struct NewCode {
    pub hash: String,
    pub client_id: String,
    pub subject: Subject,
    pub redirect_uri: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub challenge: String,
    pub expires_at: DateTime<Utc>,
}
pub struct Code {
    pub client_id: String,
    pub subject: Subject,
    pub redirect_uri: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub challenge: String,
    pub expires_at: DateTime<Utc>,
    pub consumed: bool,
    pub family_id: Option<Uuid>,
}
impl Code {
    /// Prove possession before any destructive replay response. Knowing a code
    /// alone must never let an attacker revoke the legitimate browser session.
    /// Spent codes retain this proof after redemption expiry for replay detection.
    pub fn prove_binding(&self, client: &Client, redirect: &str, verifier: &str) -> Result<()> {
        if self.client_id != client.client_id
            || self.redirect_uri != redirect
            || client.redirect(redirect).is_err()
            || !(43..=128).contains(&verifier.len())
            || !verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        {
            return Err(Error::InvalidGrant);
        }
        let calculated = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        if !bool::from(self.challenge.as_bytes().ct_eq(calculated.as_bytes())) {
            return Err(Error::InvalidGrant);
        }
        Ok(())
    }
}
pub struct Family {
    pub id: Uuid,
    pub client_id: String,
    pub subject: Subject,
    pub scope: String,
    pub nonce: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}
pub struct Refresh {
    pub family: Family,
    pub expires_at: DateTime<Utc>,
    pub consumed: bool,
}
pub struct RefreshIdentity {
    pub family_id: Uuid,
    pub client_id: String,
    pub subject: Subject,
}
pub struct ClientCredentials {
    pub client_id: String,
    pub secret: Option<String>,
    pub authenticated_method: bool,
}

#[async_trait]
pub trait SecretVerifier: Send + Sync {
    async fn verify(&self, secret: String, hash: String) -> Result<bool>;
}
#[async_trait]
pub trait GrantStore: Send + Sync {
    async fn client(&self, id: &str) -> Result<Option<Client>>;
    async fn create_code(&self, code: &NewCode) -> Result<bool>;
    async fn begin(&self) -> Result<Box<dyn GrantTransaction>>;
}
#[async_trait]
pub trait GrantTransaction: Send {
    async fn code_subject(&mut self, hash: &str) -> Result<Option<Subject>>;
    async fn refresh_identity(&mut self, hash: &str) -> Result<Option<RefreshIdentity>>;
    async fn lock_session(&mut self, subject: Subject) -> Result<Option<LiveSession>>;
    async fn lock_code(&mut self, hash: &str) -> Result<Option<Code>>;
    async fn lock_refresh(&mut self, hash: &str, family_id: Uuid) -> Result<Refresh>;
    async fn grant_code(
        &mut self,
        hash: &str,
        family: &Family,
        refresh_hash: Option<&str>,
    ) -> Result<()>;
    async fn rotate(&mut self, old_hash: &str, new_hash: &str, family: &Family) -> Result<()>;
    async fn revoke_replay(
        &mut self,
        subject: Subject,
        family_id: Uuid,
        reason: &'static str,
    ) -> Result<()>;
    async fn commit(self: Box<Self>) -> Result<()>;
}
