use crate::{config::Config, ApiError, ApiResult};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::{rngs::OsRng, RngCore};
use ring::signature::RsaKeyPair;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use spki::der::Decode;
use uuid::Uuid;

pub fn random_token() -> String {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
pub fn constant_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

pub struct PayloadCipher(Aes256Gcm);
impl PayloadCipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self(Aes256Gcm::new((&key).into()))
    }
    pub fn encrypt(&self, event_id: &str, payload: &[u8]) -> anyhow::Result<String> {
        let mut nonce = [0; 12];
        OsRng.fill_bytes(&mut nonce);
        let encrypted = self
            .0
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: payload,
                    aad: event_id.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        let mut bytes = Vec::with_capacity(12 + encrypted.len());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&encrypted);
        Ok(STANDARD.encode(bytes))
    }
    pub fn decrypt(&self, event_id: &str, payload: &str) -> anyhow::Result<Vec<u8>> {
        let bytes = STANDARD.decode(payload)?;
        if bytes.len() < 28 {
            anyhow::bail!("invalid ciphertext");
        }
        self.0
            .decrypt(
                Nonce::from_slice(&bytes[..12]),
                Payload {
                    msg: &bytes[12..],
                    aad: event_id.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("authentication failed"))
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: Uuid,
    pub sid: Uuid,
    pub exp: usize,
    pub iat: usize,
    pub token_use: String,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}
pub struct Crypto {
    signing: EncodingKey,
    active: DecodingKey,
    previous: Option<(String, DecodingKey)>,
    kid: String,
    issuer: String,
    jwks: Value,
    cipher: PayloadCipher,
    mfa_cipher: PayloadCipher,
}
impl Crypto {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let pem = std::fs::read_to_string(&config.signing_key_file)?;
        let document = pem::parse(pem.as_bytes())?;
        let key = match document.tag() {
            "PRIVATE KEY" => RsaKeyPair::from_pkcs8(document.contents()),
            "RSA PRIVATE KEY" => RsaKeyPair::from_der(document.contents()),
            _ => anyhow::bail!("RSA private key must be PKCS8 or PKCS1 PEM"),
        }
        .map_err(|_| anyhow::anyhow!("RSA private key validation failed"))?;
        let public_der = key.public().as_ref();
        let public = pkcs1::RsaPublicKey::try_from(public_der)
            .map_err(|_| anyhow::anyhow!("invalid RSA public key encoding"))?;
        let (active_jwk, active) = public_key(&public, &config.signing_kid)?;
        let mut keys = vec![active_jwk];
        let previous = if let Some(file) = &config.previous_signing_public_key_file {
            let kid = config
                .previous_signing_kid
                .clone()
                .ok_or_else(|| anyhow::anyhow!("PREVIOUS_SIGNING_KID required"))?;
            if kid == config.signing_kid {
                anyhow::bail!("active and previous kid must differ");
            }
            let pem = std::fs::read(file)?;
            let document = pem::parse(&pem)?;
            let spki;
            let public_der = match document.tag() {
                "RSA PUBLIC KEY" => document.contents(),
                "PUBLIC KEY" => {
                    spki = spki::SubjectPublicKeyInfoRef::from_der(document.contents())
                        .map_err(|_| anyhow::anyhow!("invalid RSA SPKI public key encoding"))?;
                    if spki.algorithm.oid.to_string() != "1.2.840.113549.1.1.1" {
                        anyhow::bail!("previous public key must be RSA");
                    }
                    spki.subject_public_key
                        .as_bytes()
                        .ok_or_else(|| anyhow::anyhow!("unaligned RSA public key"))?
                }
                _ => anyhow::bail!("previous public key must be PKCS1 or SPKI PEM"),
            };
            let public = pkcs1::RsaPublicKey::try_from(public_der)
                .map_err(|_| anyhow::anyhow!("invalid previous RSA public key encoding"))?;
            let (jwk, decoding) = public_key(&public, &kid)?;
            keys.push(jwk);
            Some((kid, decoding))
        } else {
            None
        };
        Ok(Self {
            signing: EncodingKey::from_rsa_pem(pem.as_bytes())?,
            active,
            previous,
            kid: config.signing_kid.clone(),
            issuer: config.issuer.clone(),
            jwks: json!({"keys":keys}),
            cipher: PayloadCipher::new(config.delivery_encryption_key),
            mfa_cipher: PayloadCipher::new(config.mfa_encryption_key),
        })
    }
    pub fn sign(&self, claims: &impl Serialize) -> ApiResult<String> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, claims, &self.signing).map_err(|_| ApiError::dependency())
    }
    pub fn verify(&self, token: &str) -> ApiResult<Claims> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| ApiError::unauthorized())?;
        if header.alg != Algorithm::RS256 {
            return Err(ApiError::unauthorized());
        }
        let key = match header.kid.as_deref() {
            Some(kid) if kid == self.kid => &self.active,
            Some(kid) => self
                .previous
                .as_ref()
                .filter(|(k, _)| k == kid)
                .map(|(_, v)| v)
                .ok_or_else(ApiError::unauthorized)?,
            None => return Err(ApiError::unauthorized()),
        };
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.validate_aud = false;
        validation.leeway = 5;
        let claims = jsonwebtoken::decode::<Claims>(token, key, &validation)
            .map_err(|_| ApiError::unauthorized())?
            .claims;
        if claims.token_use != "access"
            || claims.aud.is_empty()
            || claims.iat > chrono::Utc::now().timestamp() as usize + 5
        {
            return Err(ApiError::unauthorized());
        }
        Ok(claims)
    }
    pub fn jwks(&self) -> Value {
        self.jwks.clone()
    }
    pub fn encrypt(&self, id: &str, payload: &[u8]) -> anyhow::Result<String> {
        self.cipher.encrypt(id, payload)
    }
    pub fn decrypt(&self, id: &str, payload: &str) -> anyhow::Result<Vec<u8>> {
        self.cipher.decrypt(id, payload)
    }
    pub fn encrypt_mfa(&self, id: &str, payload: &[u8]) -> anyhow::Result<String> {
        self.mfa_cipher.encrypt(id, payload)
    }
    pub fn decrypt_mfa(&self, id: &str, payload: &str) -> anyhow::Result<Vec<u8>> {
        self.mfa_cipher.decrypt(id, payload)
    }
}
fn public_key(key: &pkcs1::RsaPublicKey<'_>, kid: &str) -> anyhow::Result<(Value, DecodingKey)> {
    let modulus = key.modulus.as_bytes();
    let bits = modulus.len() * 8
        - modulus
            .first()
            .map(|byte| byte.leading_zeros() as usize)
            .unwrap_or(0);
    if !(2048..=8192).contains(&bits) {
        anyhow::bail!("RSA modulus must contain 2048..8192 bits");
    }
    let n = URL_SAFE_NO_PAD.encode(modulus);
    let e = URL_SAFE_NO_PAD.encode(key.public_exponent.as_bytes());
    let decoding = DecodingKey::from_rsa_components(&n, &e)?;
    Ok((
        json!({"kty":"RSA","use":"sig","alg":"RS256","kid":kid,"n":n,"e":e}),
        decoding,
    ))
}
