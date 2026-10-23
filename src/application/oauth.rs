use crate::{
    domain::oauth::*,
    security::{digest, random_token, Claims, Crypto},
};
use chrono::{Duration, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use url::Url;
use uuid::Uuid;

pub struct Authorization<'a> {
    pub redirect_uri: &'a str,
    pub response_type: &'a str,
    pub response_mode: Option<&'a str>,
    pub prompt: Option<&'a str>,
    pub scope: &'a str,
    pub nonce: Option<&'a str>,
    pub challenge: Option<&'a str>,
    pub challenge_method: Option<&'a str>,
}
pub struct ApprovedAuthorization {
    pub redirect: Url,
    client_id: String,
    redirect_uri: String,
    scope: String,
    nonce: Option<String>,
    challenge: String,
}
pub struct AuthorizationFailure {
    pub redirect: Option<Url>,
    pub error: Error,
}

pub struct OAuth<'a> {
    store: &'a dyn GrantStore,
    crypto: &'a Crypto,
    issuer: &'a str,
}
impl<'a> OAuth<'a> {
    pub fn new(store: &'a dyn GrantStore, crypto: &'a Crypto, issuer: &'a str) -> Self {
        Self {
            store,
            crypto,
            issuer,
        }
    }
    pub async fn authorization(
        &self,
        client_id: &str,
        request: Authorization<'_>,
    ) -> std::result::Result<ApprovedAuthorization, AuthorizationFailure> {
        let client = self
            .store
            .client(client_id)
            .await
            .map_err(|error| AuthorizationFailure {
                redirect: None,
                error,
            })?
            .ok_or(AuthorizationFailure {
                redirect: None,
                error: Error::InvalidRequest,
            })?;
        let redirect =
            client
                .redirect(request.redirect_uri)
                .map_err(|error| AuthorizationFailure {
                    redirect: None,
                    error,
                })?;
        let validate = || -> Result<ApprovedAuthorization> {
            if request.response_type != "code" {
                return Err(Error::UnsupportedResponseType);
            }
            if request.response_mode.is_some_and(|value| value != "query")
                || request.prompt.is_some_and(|value| value != "none")
            {
                return Err(Error::InvalidRequest);
            }
            let scope = client.scope(request.scope)?;
            let challenge = request.challenge.ok_or(Error::InvalidRequest)?;
            validate_challenge(
                challenge,
                request.challenge_method.ok_or(Error::InvalidRequest)?,
            )?;
            Ok(ApprovedAuthorization {
                redirect: redirect.clone(),
                client_id: client.client_id.clone(),
                redirect_uri: request.redirect_uri.to_owned(),
                scope,
                nonce: request.nonce.map(str::to_owned),
                challenge: challenge.to_owned(),
            })
        };
        validate().map_err(|error| AuthorizationFailure {
            redirect: Some(redirect),
            error,
        })
    }
    pub async fn authorize(
        &self,
        subject: Subject,
        approved: &ApprovedAuthorization,
    ) -> Result<String> {
        let code = random_token();
        let inserted = self
            .store
            .create_code(&NewCode {
                hash: digest(&code),
                client_id: approved.client_id.clone(),
                subject,
                redirect_uri: approved.redirect_uri.clone(),
                scope: approved.scope.clone(),
                nonce: approved.nonce.clone(),
                challenge: approved.challenge.clone(),
                expires_at: Utc::now() + Duration::seconds(CODE_TTL_SECONDS),
            })
            .await?;
        if !inserted {
            return Err(Error::LoginRequired);
        }
        Ok(code)
    }
    pub async fn authenticate_client(
        &self,
        credentials: ClientCredentials,
        verifier: &dyn SecretVerifier,
    ) -> Result<Client> {
        let client = self
            .store
            .client(&credentials.client_id)
            .await?
            .ok_or(Error::InvalidClient)?;
        if client.is_public {
            if credentials.authenticated_method || credentials.secret.is_some() {
                return Err(Error::InvalidClient);
            }
        } else {
            let secret = credentials
                .secret
                .filter(|secret| !secret.is_empty())
                .ok_or(Error::InvalidClient)?;
            let hash = client.secret_hash.clone().ok_or(Error::InvalidClient)?;
            if !verifier.verify(secret, hash).await? {
                return Err(Error::InvalidClient);
            }
        }
        Ok(client)
    }
    pub async fn exchange_code(
        &self,
        client: &Client,
        code: &str,
        redirect: &str,
        verifier: &str,
    ) -> Result<TokenResponse> {
        if code.is_empty() {
            return Err(Error::InvalidRequest);
        }
        let hash = digest(code);
        let mut tx = self.store.begin().await?;
        tx.lock_client(client).await?;
        // Mutation lock order: client -> user -> session -> code/family/refresh.
        let subject = tx.code_subject(&hash).await?.ok_or(Error::InvalidGrant)?;
        let live = tx.lock_session(subject).await?;
        let code = tx.lock_code(&hash).await?.ok_or(Error::InvalidGrant)?;
        code.prove_binding(client, redirect, verifier)?;
        if code.subject.user_id != subject.user_id || code.subject.session_id != subject.session_id
        {
            return Err(Error::InvalidGrant);
        }
        if code.consumed {
            if let Some(family) = code.family_id {
                tx.revoke_replay(subject, family, "oauth_code_reuse")
                    .await?;
                tx.commit().await?;
            }
            return Err(Error::InvalidGrant);
        }
        if code.expires_at <= Utc::now() {
            return Err(Error::InvalidGrant);
        }
        let session = live.ok_or(Error::InvalidGrant)?;
        let scope = client.scope(&code.scope)?;
        let family = Family {
            id: Uuid::new_v4(),
            client_id: client.client_id.clone(),
            subject,
            scope,
            nonce: code.nonce,
            expires_at: session
                .expires_at
                .min(Utc::now() + Duration::days(REFRESH_TTL_DAYS)),
            revoked: false,
        };
        let refresh = has_scope(&family.scope, "offline_access").then(random_token);
        let refresh_hash = refresh.as_deref().map(digest);
        tx.grant_code(&hash, &family, refresh_hash.as_deref())
            .await?;
        let response = self.tokens(&session, &family, refresh)?;
        tx.commit().await?;
        Ok(response)
    }
    pub async fn exchange_refresh(
        &self,
        client: &Client,
        token: &str,
        requested_scope: Option<&str>,
    ) -> Result<TokenResponse> {
        if token.is_empty() {
            return Err(Error::InvalidRequest);
        }
        let hash = digest(token);
        let mut tx = self.store.begin().await?;
        tx.lock_client(client).await?;
        let identity = tx
            .refresh_identity(&hash)
            .await?
            .ok_or(Error::InvalidGrant)?;
        if identity.client_id != client.client_id {
            return Err(Error::InvalidGrant);
        }
        let live = tx.lock_session(identity.subject).await?;
        let refresh = tx.lock_refresh(&hash, identity.family_id).await?;
        let mut family = refresh.family;
        if refresh.consumed {
            tx.revoke_replay(identity.subject, family.id, "oauth_refresh_reuse")
                .await?;
            tx.commit().await?;
            return Err(Error::InvalidGrant);
        }
        let session = live.ok_or(Error::InvalidGrant)?;
        if family.revoked || family.expires_at <= Utc::now() || refresh.expires_at <= Utc::now() {
            return Err(Error::InvalidGrant);
        }
        let scope = client.scope(requested_scope.unwrap_or(&family.scope))?;
        if scope.split(' ').any(|part| !has_scope(&family.scope, part)) {
            return Err(Error::InvalidScope);
        }
        family.scope = scope;
        family.expires_at = family.expires_at.min(session.expires_at);
        let next = random_token();
        tx.rotate(&hash, &digest(&next), &family).await?;
        let response = self.tokens(&session, &family, Some(next))?;
        tx.commit().await?;
        Ok(response)
    }
    fn tokens(
        &self,
        session: &LiveSession,
        family: &Family,
        refresh_token: Option<String>,
    ) -> Result<TokenResponse> {
        let now = Utc::now();
        let expires_in = ACCESS_TTL_SECONDS.min((session.expires_at - now).num_seconds());
        if expires_in <= 0 {
            return Err(Error::InvalidGrant);
        }
        let claims = Claims {
            iss: self.issuer.to_owned(),
            aud: family.client_id.clone(),
            sub: session.subject.user_id,
            sid: session.subject.session_id,
            exp: (now.timestamp() + expires_in) as usize,
            iat: now.timestamp() as usize,
            token_use: "access".to_owned(),
            scope: family.scope.clone(),
            grant_id: Some(family.id),
            nonce: None,
            email: None,
            email_verified: None,
        };
        let access_token = self.crypto.sign(&claims).map_err(|_| Error::Dependency)?;
        let id = Claims {
            token_use: "id".to_owned(),
            grant_id: None,
            nonce: family.nonce.clone(),
            email: has_scope(&family.scope, "email").then(|| session.email.clone()),
            email_verified: has_scope(&family.scope, "email").then_some(session.email_verified),
            ..claims
        };
        let id_token = self.crypto.sign(&id).map_err(|_| Error::Dependency)?;
        Ok(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in,
            scope: family.scope.clone(),
            id_token,
            refresh_token,
        })
    }
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub scope: String,
    pub id_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}
pub fn userinfo(claims: &Claims, subject: Subject, email: &str, verified: bool) -> Result<Value> {
    if claims.token_use != "access"
        || claims.sub != subject.user_id
        || claims.sid != subject.session_id
    {
        return Err(Error::InvalidToken);
    }
    if !has_scope(&claims.scope, "openid") {
        return Err(Error::InsufficientScope);
    }
    let mut info = json!({"sub": subject.user_id.to_string()});
    if has_scope(&claims.scope, "email") {
        info["email"] = json!(email);
        info["email_verified"] = json!(verified);
    }
    Ok(info)
}
