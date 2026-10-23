use identity_service::{
    config::Config,
    security::{Claims, Crypto},
};
use uuid::Uuid;

#[test]
#[ignore = "requires generated RSA signing PEM and full identity config"]
fn ring_validated_key_publishes_only_public_jwks_that_verifies_rs256_signature() {
    let config = Config::from_env().unwrap();
    let crypto = Crypto::new(&config).unwrap();
    let now = chrono::Utc::now().timestamp() as usize;
    let claims = Claims {
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
    };
    let token = crypto.sign(&claims).unwrap();
    let jwks = crypto.jwks();
    let key = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["kid"] == config.signing_kid)
        .unwrap();
    assert_eq!(key["kty"], "RSA");
    assert_eq!(key["alg"], "RS256");
    for private in ["d", "p", "q", "dp", "dq", "qi"] {
        assert!(key.get(private).is_none());
    }
    let decoding = jsonwebtoken::DecodingKey::from_rsa_components(
        key["n"].as_str().unwrap(),
        key["e"].as_str().unwrap(),
    )
    .unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&[config.issuer]);
    validation.set_audience(&[config.public_origin]);
    let verified = jsonwebtoken::decode::<Claims>(&token, &decoding, &validation).unwrap();
    assert_eq!(verified.claims.sub, claims.sub);
    assert_eq!(verified.claims.sid, claims.sid);
}
#[test]
#[ignore = "requires full identity config; uses actual OpenSSL CLI to generate disposable weak key only"]
fn signing_configuration_rejects_rsa_modulus_below_2048_bits() {
    let mut config = Config::from_env().unwrap();
    let path = std::env::temp_dir().join(format!("identity-weak-{}.pem", Uuid::new_v4()));
    let status = std::process::Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:1024",
            "-out",
        ])
        .arg(&path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    config.signing_key_file = path.to_string_lossy().into_owned();
    let rejected = Crypto::new(&config).is_err();
    std::fs::remove_file(path).unwrap();
    assert!(rejected);
}
