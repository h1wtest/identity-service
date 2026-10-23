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

#[tokio::test]
#[ignore = "requires full identity env and actual OpenSSL fixture CLI"]
async fn https_certificate_chain_accepts_pkcs8_and_pkcs1_and_rejects_mismatched_keys() {
    let keys = Keys::new();
    keys.rsa("tls-pkcs8.pem", "2048");
    keys.rsa("wrong.pem", "2048");
    keys.openssl(&[
        "rsa",
        "-in",
        "tls-pkcs8.pem",
        "-traditional",
        "-out",
        "tls-pkcs1.pem",
    ]);
    keys.openssl(&[
        "req",
        "-new",
        "-x509",
        "-key",
        "tls-pkcs8.pem",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost",
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-addext",
        "extendedKeyUsage=serverAuth",
        "-days",
        "1",
        "-out",
        "cert.pem",
    ]);
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificate = std::fs::read(keys.path("cert.pem")).unwrap();
    let chain = [certificate.as_slice(), certificate.as_slice()].concat();
    std::fs::write(keys.path("chain.pem"), &chain).unwrap();
    for key in ["tls-pkcs8.pem", "tls-pkcs1.pem"] {
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            keys.path("chain.pem"),
            keys.path(key),
        )
        .await
        .unwrap();
        use rustls_pki_types::{pem::PemObject, CertificateDer, ServerName};
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(&certificate).unwrap())
            .unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client = rustls::ClientConnection::new(
            std::sync::Arc::new(client_config),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut server = rustls::ServerConnection::new(tls.get_inner()).unwrap();
        for _ in 0..10 {
            let mut to_server = Vec::new();
            client.write_tls(&mut to_server).unwrap();
            server
                .read_tls(&mut std::io::Cursor::new(to_server))
                .unwrap();
            server.process_new_packets().unwrap();
            let mut to_client = Vec::new();
            server.write_tls(&mut to_client).unwrap();
            client
                .read_tls(&mut std::io::Cursor::new(to_client))
                .unwrap();
            client.process_new_packets().unwrap();
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
        assert_eq!(client.peer_certificates().unwrap().len(), 2);
    }
    assert!(axum_server::tls_rustls::RustlsConfig::from_pem_file(
        keys.path("chain.pem"),
        keys.path("wrong.pem"),
    )
    .await
    .is_err());
}

#[tokio::test]
#[ignore = "requires full identity env and actual OpenSSL fixture CLI"]
async fn kafka_ca_rejects_empty_malformed_and_invalid_certificates_before_connecting() {
    let keys = Keys::new();
    let mut config = Config::from_env().unwrap();
    config.kafka_tls_ca_file = keys.path("ca.pem").to_string_lossy().into_owned();
    config.kafka_brokers = vec!["127.0.0.1:1".into()];
    std::fs::write(keys.path("ca.pem"), b"not a certificate").unwrap();
    let Err(error) = identity_service::adapters::kafka::client(&config).await else {
        panic!("empty CA must fail before opening a broker connection");
    };
    assert_eq!(error.to_string(), "Kafka TLS CA contains no certificates");
    std::fs::write(
        keys.path("ca.pem"),
        b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let Err(error) = identity_service::adapters::kafka::client(&config).await else {
        panic!("malformed CA must fail before opening a broker connection");
    };
    assert!(error
        .downcast_ref::<rustls_pki_types::pem::Error>()
        .is_some());
    std::fs::write(
        keys.path("ca.pem"),
        b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let Err(error) = identity_service::adapters::kafka::client(&config).await else {
        panic!("invalid certificate DER must fail before opening a broker connection");
    };
    assert!(error.downcast_ref::<rustls::Error>().is_some());
}
