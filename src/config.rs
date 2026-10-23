use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub public_origin: String,
    pub issuer: String,
    pub signing_key_file: String,
    pub signing_kid: String,
    pub previous_signing_public_key_file: Option<String>,
    pub previous_signing_kid: Option<String>,
    pub mfa_encryption_key: [u8; 32],
    pub delivery_encryption_key: [u8; 32],
    pub http_port: u16,
    pub session_ttl_seconds: i64,
    pub kafka_brokers: Vec<String>,
    pub kafka_tls_ca_file: String,
    pub kafka_sasl_username: String,
    pub kafka_sasl_password: String,
    pub tls_cert_file: String,
    pub tls_key_file: String,
    pub profile_internal_token: String,
    pub notification_internal_token: String,
    pub admin_internal_token: String,
    pub gateway_internal_token: String,
}
impl Config {
    pub fn from_env() -> Result<Self> {
        let required = |name: &str| -> Result<String> {
            let value = std::env::var(name).with_context(|| format!("{name} required"))?;
            if value.is_empty() {
                bail!("{name} must not be empty");
            }
            Ok(value)
        };
        let public_origin = required("PUBLIC_ORIGIN")?;
        let origin = url::Url::parse(&public_origin)?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !origin.username().is_empty()
        {
            bail!("PUBLIC_ORIGIN must be an HTTPS origin");
        }
        let issuer = std::env::var("OAUTH_ISSUER").unwrap_or_else(|_| public_origin.clone());
        if !issuer.starts_with("https://") {
            bail!("OAUTH_ISSUER must use HTTPS");
        }
        let parse_key = |name: &str| -> Result<[u8; 32]> {
            STANDARD
                .decode(required(name)?)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("{name} must encode 32 bytes"))
        };
        let mfa_encryption_key = parse_key("MFA_ENCRYPTION_KEY")?;
        let delivery_encryption_key = parse_key("DELIVERY_ENCRYPTION_KEY")?;
        if mfa_encryption_key == delivery_encryption_key {
            bail!("MFA and delivery encryption keys must be distinct");
        }
        let profile_internal_token = required("PROFILE_INTERNAL_TOKEN")?;
        let notification_internal_token = required("NOTIFICATION_INTERNAL_TOKEN")?;
        let admin_internal_token = required("ADMIN_INTERNAL_TOKEN")?;
        for token in [
            &profile_internal_token,
            &notification_internal_token,
            &admin_internal_token,
        ] {
            if token.len() < 32 {
                bail!("internal tokens must be at least 32 characters");
            }
        }
        if profile_internal_token == notification_internal_token
            || profile_internal_token == admin_internal_token
            || notification_internal_token == admin_internal_token
        {
            bail!("service credentials must be distinct");
        }
        let gateway_internal_token = required("GATEWAY_INTERNAL_TOKEN")?;
        if gateway_internal_token.len() < 32
            || [
                &profile_internal_token,
                &notification_internal_token,
                &admin_internal_token,
            ]
            .contains(&&gateway_internal_token)
        {
            bail!("gateway credential must be distinct and at least 32 characters");
        }
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            public_origin: public_origin.trim_end_matches('/').into(),
            issuer: issuer.trim_end_matches('/').into(),
            signing_key_file: required("SIGNING_KEY_FILE")?,
            signing_kid: required("SIGNING_KID")?,
            previous_signing_public_key_file: std::env::var("PREVIOUS_SIGNING_PUBLIC_KEY_FILE")
                .ok(),
            previous_signing_kid: std::env::var("PREVIOUS_SIGNING_KID").ok(),
            mfa_encryption_key,
            delivery_encryption_key,
            http_port: std::env::var("HTTP_PORT")
                .unwrap_or_else(|_| "8001".into())
                .parse()?,
            session_ttl_seconds: 86400,
            kafka_brokers: required("KAFKA_BROKERS")?
                .split(',')
                .map(str::to_owned)
                .collect(),
            kafka_tls_ca_file: required("KAFKA_TLS_CA_FILE")?,
            kafka_sasl_username: required("KAFKA_SASL_USERNAME")?,
            kafka_sasl_password: required("KAFKA_SASL_PASSWORD")?,
            tls_cert_file: required("TLS_CERT_FILE")?,
            tls_key_file: required("TLS_KEY_FILE")?,
            profile_internal_token,
            notification_internal_token,
            admin_internal_token,
            gateway_internal_token,
        })
    }
}
