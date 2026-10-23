use identity_service::{rekey, security::PayloadCipher};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; real AES-GCM and PostgreSQL"]
async fn existing_common_ciphertext_rekeys_atomically_and_unknown_cipher_rolls_back() {
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let schema = format!("rekey_{}", Uuid::new_v4().simple());
    let setup = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&setup)
        .await
        .unwrap();
    let search = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |connection, _| {
            let command = format!("SET search_path TO {search}");
            Box::pin(async move {
                sqlx::query(&command).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TABLE mfa_secrets(user_id uuid PRIMARY KEY,secret_key text NOT NULL,updated_at timestamptz DEFAULT now());CREATE TABLE pending_mfa(user_id uuid PRIMARY KEY,encrypted_secret text NOT NULL);CREATE TABLE outbox_events(id uuid PRIMARY KEY,event_type text NOT NULL,payload jsonb NOT NULL)").execute(&pool).await.unwrap();
    let uid = Uuid::new_v4();
    let event_id = Uuid::new_v4();
    let old = PayloadCipher::new([1; 32]);
    let mfa = PayloadCipher::new([2; 32]);
    let delivery = PayloadCipher::new([3; 32]);
    let original = old.encrypt(&uid.to_string(), b"JBSWY3DPEHPK3PXP").unwrap();
    let pending = old.encrypt(&uid.to_string(), b"PENDINGSECRET").unwrap();
    sqlx::query("INSERT INTO mfa_secrets(user_id,secret_key) VALUES($1,$2)")
        .bind(uid)
        .bind(format!("enc:{original}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO pending_mfa(user_id,encrypted_secret) VALUES($1,$2)")
        .bind(uid)
        .bind(&pending)
        .execute(&pool)
        .await
        .unwrap();
    let payload = serde_json::json!({"user_id":uid,"email":"rekey@test.invalid","token":"private-reset-token","expires_at":"2026-10-23T12:00:00Z"});
    let encrypted = old
        .encrypt(
            &event_id.to_string(),
            &serde_json::to_vec(&payload).unwrap(),
        )
        .unwrap();
    let envelope = serde_json::json!({"schema_version":1,"event_id":event_id,"event_type":"notification.password_reset","aggregate_id":uid,"occurred_at":"2026-10-23T11:00:00Z","encrypted_payload":encrypted});
    sqlx::query("INSERT INTO outbox_events(id,event_type,payload) VALUES($1,'notification.password_reset',$2)").bind(event_id).bind(envelope).execute(&pool).await.unwrap();
    let broken_uid = Uuid::new_v4();
    let broken = PayloadCipher::new([9; 32])
        .encrypt(&broken_uid.to_string(), b"unknown-secret")
        .unwrap();
    sqlx::query("INSERT INTO pending_mfa(user_id,encrypted_secret) VALUES($1,$2)")
        .bind(broken_uid)
        .bind(broken)
        .execute(&pool)
        .await
        .unwrap();
    assert!(rekey::run(&pool, [1; 32], [2; 32], [3; 32]).await.is_err());
    let unchanged: String =
        sqlx::query_scalar("SELECT secret_key FROM mfa_secrets WHERE user_id=$1")
            .bind(uid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(unchanged, format!("enc:{original}"));
    sqlx::query("DELETE FROM pending_mfa WHERE user_id=$1")
        .bind(broken_uid)
        .execute(&pool)
        .await
        .unwrap();
    rekey::run(&pool, [1; 32], [2; 32], [3; 32]).await.unwrap();
    let sealed: String = sqlx::query_scalar("SELECT secret_key FROM mfa_secrets WHERE user_id=$1")
        .bind(uid)
        .fetch_one(&pool)
        .await
        .unwrap();
    let sealed = sealed.strip_prefix("enc:").unwrap();
    assert_eq!(
        mfa.decrypt(&uid.to_string(), sealed).unwrap(),
        b"JBSWY3DPEHPK3PXP"
    );
    assert!(old.decrypt(&uid.to_string(), sealed).is_err());
    let sealed_pending: String =
        sqlx::query_scalar("SELECT encrypted_secret FROM pending_mfa WHERE user_id=$1")
            .bind(uid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        mfa.decrypt(&uid.to_string(), &sealed_pending).unwrap(),
        b"PENDINGSECRET"
    );
    let migrated: serde_json::Value =
        sqlx::query_scalar("SELECT payload FROM outbox_events WHERE id=$1")
            .bind(event_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let command = migrated["encrypted_payload"].as_str().unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &delivery.decrypt(&event_id.to_string(), command).unwrap()
        )
        .unwrap(),
        payload
    );
    assert!(old.decrypt(&event_id.to_string(), command).is_err());
    rekey::run(&pool, [1; 32], [2; 32], [3; 32]).await.unwrap();
    let twice: serde_json::Value =
        sqlx::query_scalar("SELECT payload FROM outbox_events WHERE id=$1")
            .bind(event_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(migrated, twice);
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&setup)
        .await
        .unwrap();
}
