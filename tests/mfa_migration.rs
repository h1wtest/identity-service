use identity_service::{config::Config, security::PayloadCipher};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL and full identity configuration; serial environment mutation"]
async fn legacy_factor_cutover_failure_rolls_back_then_correct_key_retry_is_idempotent() {
    let config = Config::from_env().unwrap();
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let schema = format!("mfa_migration_{}", Uuid::new_v4().simple());
    let setup = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&setup)
        .await
        .unwrap();
    let search_schema = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |connection, _| {
            let query = format!("SET search_path TO {search_schema}");
            Box::pin(async move {
                sqlx::query(&query).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE mfa_secrets(user_id uuid PRIMARY KEY,secret_key text NOT NULL,updated_at timestamptz NOT NULL DEFAULT now())").execute(&pool).await.unwrap();
    let uid = Uuid::new_v4();
    sqlx::query("INSERT INTO mfa_secrets(user_id,secret_key) VALUES($1,'JBSWY3DPEHPK3PXP')")
        .bind(uid)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE mfa_secrets ADD CONSTRAINT mfa_secret_encrypted CHECK(secret_key LIKE 'enc:%') NOT VALID").execute(&pool).await.unwrap();
    let original = std::env::var("MFA_ENCRYPTION_KEY").unwrap();
    std::env::remove_var("MFA_ENCRYPTION_KEY");
    let missing = identity_service::encrypt_legacy_mfa(&pool).await;
    std::env::set_var("MFA_ENCRYPTION_KEY", "invalid-base64!");
    let malformed = identity_service::encrypt_legacy_mfa(&pool).await;
    std::env::set_var("MFA_ENCRYPTION_KEY", &original);
    assert!(missing.is_err());
    assert!(malformed.is_err());
    let plaintext: String =
        sqlx::query_scalar("SELECT secret_key FROM mfa_secrets WHERE user_id=$1")
            .bind(uid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(plaintext, "JBSWY3DPEHPK3PXP");
    let validated:bool=sqlx::query_scalar("SELECT convalidated FROM pg_constraint WHERE conrelid='mfa_secrets'::regclass AND conname='mfa_secret_encrypted'").fetch_one(&pool).await.unwrap();
    assert!(!validated);
    identity_service::encrypt_legacy_mfa(&pool).await.unwrap();
    let sealed: String = sqlx::query_scalar("SELECT secret_key FROM mfa_secrets WHERE user_id=$1")
        .bind(uid)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        PayloadCipher::new(config.mfa_encryption_key)
            .decrypt(&uid.to_string(), sealed.strip_prefix("enc:").unwrap())
            .unwrap(),
        b"JBSWY3DPEHPK3PXP"
    );
    identity_service::encrypt_legacy_mfa(&pool).await.unwrap();
    let second: String = sqlx::query_scalar("SELECT secret_key FROM mfa_secrets WHERE user_id=$1")
        .bind(uid)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(sealed, second);
    let validated:bool=sqlx::query_scalar("SELECT convalidated FROM pg_constraint WHERE conrelid='mfa_secrets'::regclass AND conname='mfa_secret_encrypted'").fetch_one(&pool).await.unwrap();
    assert!(validated);
    assert!(
        sqlx::query("INSERT INTO mfa_secrets(user_id,secret_key) VALUES($1,'PLAINTEXT')")
            .bind(Uuid::new_v4())
            .execute(&pool)
            .await
            .is_err()
    );
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&setup)
        .await
        .unwrap();
}
