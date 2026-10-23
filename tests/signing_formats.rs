use identity_service::{
    config::Config,
    security::{Claims, Crypto},
};
use std::path::{Path, PathBuf};
use uuid::Uuid;

struct Keys(PathBuf);
impl Keys {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("identity-rsa-formats-{}", Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn openssl(&self, args: &[&str]) {
        let status = std::process::Command::new("openssl")
            .args(args)
            .current_dir(&self.0)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "OpenSSL fixture command failed");
    }
    fn rsa(&self, name: &str, bits: &str) {
        self.openssl(&[
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            &format!("rsa_keygen_bits:{bits}"),
            "-out",
            name,
        ]);
    }
}
impl Drop for Keys {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn config(key: &Path, kid: &str) -> Config {
    let mut config = Config::from_env().unwrap();
    config.signing_key_file = key.to_string_lossy().into_owned();
    config.signing_kid = kid.into();
    config.previous_signing_public_key_file = None;
    config.previous_signing_kid = None;
    config
}
fn claims(config: &Config) -> Claims {
    let now = chrono::Utc::now().timestamp() as usize;
    Claims {
        iss: config.issuer.clone(),
        aud: config.public_origin.clone(),
        sub: Uuid::new_v4(),
        sid: Uuid::new_v4(),
        exp: now + 300,
        iat: now,
        token_use: "access".into(),
        scope: "platform:api".into(),
        nonce: None,
        email: None,
        email_verified: None,
    }
}

#[test]
#[ignore = "requires full identity env and actual OpenSSL fixture CLI"]
fn active_pkcs8_and_pkcs1_publish_identical_public_keys_and_verify_signatures() {
    let keys = Keys::new();
    keys.rsa("active-pkcs8.pem", "2048");
    keys.openssl(&[
        "rsa",
        "-in",
        "active-pkcs8.pem",
        "-traditional",
        "-out",
        "active-pkcs1.pem",
    ]);
    let first_config = config(&keys.path("active-pkcs8.pem"), "active");
    let second_config = config(&keys.path("active-pkcs1.pem"), "active");
    let first = Crypto::new(&first_config).unwrap();
    let second = Crypto::new(&second_config).unwrap();
    assert_eq!(first.jwks(), second.jwks());
    let claims = claims(&first_config);
    let from_pkcs8 = first.sign(&claims).unwrap();
    let from_pkcs1 = second.sign(&claims).unwrap();
    assert_eq!(second.verify(&from_pkcs8).unwrap().sub, claims.sub);
    assert_eq!(first.verify(&from_pkcs1).unwrap().sid, claims.sid);
}
#[test]
#[ignore = "requires full identity env and actual OpenSSL fixture CLI"]
fn previous_spki_and_pkcs1_keys_verify_old_tokens_after_rotation() {
    let keys = Keys::new();
    keys.rsa("old.pem", "2048");
    keys.rsa("active.pem", "2048");
    keys.openssl(&["rsa", "-in", "old.pem", "-pubout", "-out", "old-spki.pem"]);
    keys.openssl(&[
        "rsa",
        "-in",
        "old.pem",
        "-RSAPublicKey_out",
        "-out",
        "old-pkcs1.pem",
    ]);
    let old_config = config(&keys.path("old.pem"), "old");
    let old = Crypto::new(&old_config).unwrap();
    let claims = claims(&old_config);
    let old_token = old.sign(&claims).unwrap();
    for public in ["old-spki.pem", "old-pkcs1.pem"] {
        let mut rotated = config(&keys.path("active.pem"), "active");
        rotated.previous_signing_public_key_file =
            Some(keys.path(public).to_string_lossy().into_owned());
        rotated.previous_signing_kid = Some("old".into());
        let crypto = Crypto::new(&rotated).unwrap();
        assert_eq!(crypto.jwks()["keys"].as_array().unwrap().len(), 2);
        assert_eq!(crypto.verify(&old_token).unwrap().sub, claims.sub);
        assert!(old.verify(&crypto.sign(&claims).unwrap()).is_err());
    }
}
#[test]
#[ignore = "requires full identity env and actual OpenSSL fixture CLI"]
fn missing_or_wrong_kid_and_hs256_algorithm_are_rejected() {
    let keys = Keys::new();
    keys.rsa("active.pem", "2048");
    let config = config(&keys.path("active.pem"), "active");
    let crypto = Crypto::new(&config).unwrap();
    let claims = claims(&config);
    let pem = std::fs::read(keys.path("active.pem")).unwrap();
    let encoding = jsonwebtoken::EncodingKey::from_rsa_pem(&pem).unwrap();
    for kid in [None, Some("unknown".to_string())] {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = kid;
        let token = jsonwebtoken::encode(&header, &claims, &encoding).unwrap();
        assert!(crypto.verify(&token).is_err());
    }
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some("active".into());
    let token = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(b"attacker-controlled-hmac-key"),
    )
    .unwrap();
    assert!(crypto.verify(&token).is_err());
}
#[test]
#[ignore = "requires full identity env and actual OpenSSL fixture CLI"]
fn previous_ec_oid_and_weak_rsa_key_are_rejected() {
    let keys = Keys::new();
    keys.rsa("active.pem", "2048");
    keys.rsa("weak.pem", "1024");
    keys.openssl(&[
        "rsa",
        "-in",
        "weak.pem",
        "-pubout",
        "-out",
        "weak-public.pem",
    ]);
    keys.openssl(&[
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-out",
        "ec.pem",
    ]);
    keys.openssl(&["pkey", "-in", "ec.pem", "-pubout", "-out", "ec-public.pem"]);
    for public in ["weak-public.pem", "ec-public.pem"] {
        let mut config = config(&keys.path("active.pem"), "active");
        config.previous_signing_public_key_file =
            Some(keys.path(public).to_string_lossy().into_owned());
        config.previous_signing_kid = Some("old".into());
        assert!(Crypto::new(&config).is_err());
    }
}
