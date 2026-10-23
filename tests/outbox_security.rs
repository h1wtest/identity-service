use identity_service::{
    domain::events::partition_for,
    outbox::{acknowledge, claim, retry},
};
use sqlx::PgPool;
use uuid::Uuid;

async fn database() -> PgPool {
    let pool = PgPool::connect(
        &std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must name a disposable migrated PostgreSQL database"),
    )
    .await
    .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    pool
}

async fn insert(pool: &PgPool, aggregate: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let payload = serde_json::json!({"schema_version":1,"event_id":id,"event_type":"identity.email_verified","aggregate_id":aggregate,"occurred_at":"2026-10-23T00:00:00Z","payload":{"user_id":aggregate}});
    sqlx::query("INSERT INTO outbox_events(id,event_type,aggregate_id,topic,payload) VALUES($1,'identity.email_verified',$2,'identity.events.v1',$3)").bind(id).bind(aggregate.to_string()).bind(payload).execute(pool).await.unwrap();
    id
}

#[tokio::test]
#[ignore = "requires isolated real PostgreSQL TEST_DATABASE_URL; run serially"]
async fn independent_workers_cannot_overtake_an_unacknowledged_aggregate() {
    let pool = database().await;
    let aggregate = Uuid::new_v4();
    let first = insert(&pool, aggregate).await;
    let second = insert(&pool, aggregate).await;
    let a = claim(&pool).await.unwrap().unwrap();
    assert_eq!(a.id, first);
    assert!(claim(&pool).await.unwrap().is_none());
    assert!(acknowledge(&pool, &a).await.unwrap());
    let b = claim(&pool).await.unwrap().unwrap();
    assert_eq!(b.id, second);
    assert!(acknowledge(&pool, &b).await.unwrap());
    sqlx::query("DELETE FROM outbox_events WHERE aggregate_id=$1")
        .bind(aggregate.to_string())
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires isolated real PostgreSQL TEST_DATABASE_URL; run serially"]
async fn expired_claim_is_recovered_with_stable_id_and_stale_owner_is_fenced() {
    let pool = database().await;
    let aggregate = Uuid::new_v4();
    let event = insert(&pool, aggregate).await;
    let old = claim(&pool).await.unwrap().unwrap();
    sqlx::query("UPDATE outbox_events SET lease_until=now()-interval '1 second' WHERE id=$1")
        .bind(event)
        .execute(&pool)
        .await
        .unwrap();
    let recovered = claim(&pool).await.unwrap().unwrap();
    assert_eq!(recovered.id, event);
    assert_ne!(old.lease_token, recovered.lease_token);
    assert_eq!(old.payload, recovered.payload);
    assert!(!acknowledge(&pool, &old).await.unwrap());
    assert!(!retry(&pool, &old).await.unwrap());
    assert!(acknowledge(&pool, &recovered).await.unwrap());
    sqlx::query("DELETE FROM outbox_events WHERE id=$1")
        .bind(event)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires isolated real PostgreSQL TEST_DATABASE_URL; run serially"]
async fn retry_is_persisted_bounded_and_blocks_only_its_aggregate() {
    let pool = database().await;
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let first = insert(&pool, a).await;
    insert(&pool, a).await;
    let claimed = claim(&pool).await.unwrap().unwrap();
    assert!(retry(&pool, &claimed).await.unwrap());
    let delay: f64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM next_attempt_at-now())::float8 FROM outbox_events WHERE id=$1",
    )
    .bind(first)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(delay > 0.0 && delay <= 300.0);
    assert!(claim(&pool).await.unwrap().is_none());
    sqlx::query("UPDATE outbox_events SET retry_count=1000,next_attempt_at=now() WHERE id=$1")
        .bind(first)
        .execute(&pool)
        .await
        .unwrap();
    let many_attempts = claim(&pool).await.unwrap().unwrap();
    assert!(retry(&pool, &many_attempts).await.unwrap());
    let capped: f64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM next_attempt_at-now())::float8 FROM outbox_events WHERE id=$1",
    )
    .bind(first)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(capped > 149.0 && capped <= 300.0);
    let independent = insert(&pool, b).await;
    let job = claim(&pool).await.unwrap().unwrap();
    assert_eq!(job.id, independent);
    acknowledge(&pool, &job).await.unwrap();
    sqlx::query("DELETE FROM outbox_events WHERE aggregate_id=ANY($1)")
        .bind(vec![a.to_string(), b.to_string()])
        .execute(&pool)
        .await
        .unwrap();
}

#[test]
fn aggregate_partition_is_stable_and_spreads_over_six_partitions() {
    let mut seen = std::collections::BTreeSet::new();
    for n in 1..1000 {
        let id = Uuid::from_u128(n);
        let p = partition_for(id);
        assert!((0..6).contains(&p));
        assert_eq!(p, partition_for(id));
        seen.insert(p);
    }
    assert_eq!(seen.len(), 6);
}

#[test]
fn independently_derived_ciphertext_requires_exact_event_id_aad() {
    let cipher = identity_service::security::PayloadCipher::new([0x11; 32]);
    let wire = "IiIiIiIiIiIiIiIibNVyOqW9wDaBHeQeeJfQtC+j/dJHsZx7YmI92DnRSDt1T5svY5jJ7n5o3R3WaHkHkf68B/gTE5KWTsifixObxwrpXF0p5DxihwQY+Hmfn2CM2YESIY20Nzwj64gPkDLgvXdxMlsy8z417ohkKzrrB1k72JdiGeoMsxZVHUXeJuJ0qNrPqVsKDldIyCTy/6F2vVZ5EUWFOXs=";
    let plaintext = cipher
        .decrypt("019a0000-0000-7000-8000-000000000001", wire)
        .unwrap();
    assert_eq!(
        String::from_utf8(plaintext).unwrap(),
        r#"{"user_id":"019a0000-0000-7000-8000-000000000002","email":"fixture@example.invalid","code":"123456","expires_at":"2026-10-23T12:00:00Z"}"#
    );
    assert!(cipher
        .decrypt("019a0000-0000-7000-8000-000000000003", wire)
        .is_err());
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and real signing/encryption environment; run serially"]
async fn sensitive_enqueue_is_encrypted_before_sql_and_atomic_with_authoritative_state() {
    use identity_service::{config::Config, events::enqueue, security::Crypto};
    let pool = database().await;
    let crypto = Crypto::new(&Config::from_env().unwrap()).unwrap();
    let uid = Uuid::new_v4();
    let email = format!("{uid}@test.invalid");
    let payload = serde_json::json!({"user_id":uid,"email":email,"code":"nonpublic-code-91372","expires_at":"2026-10-23T12:00:00Z"});
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO users(id,email,password_hash) VALUES($1,$2,'not-used')")
        .bind(uid)
        .bind(&email)
        .execute(&mut *tx)
        .await
        .unwrap();
    let event_id = enqueue(
        &mut tx,
        &crypto,
        "notification.email_verification",
        uid,
        payload.clone(),
        None,
    )
    .await
    .unwrap();
    let stored: serde_json::Value =
        sqlx::query_scalar("SELECT payload FROM outbox_events WHERE id=$1")
            .bind(event_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert!(!stored.to_string().contains("nonpublic-code-91372"));
    assert!(stored.get("payload").is_none());
    assert_eq!(stored["event_id"], event_id.to_string());
    let decrypted = crypto
        .decrypt(
            &event_id.to_string(),
            stored["encrypted_payload"].as_str().unwrap(),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&decrypted).unwrap(),
        payload
    );
    tx.rollback().await.unwrap();
    assert!(!sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM outbox_events WHERE id=$1)"
    )
    .bind(event_id)
    .fetch_one(&pool)
    .await
    .unwrap());
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)")
            .bind(uid)
            .fetch_one(&pool)
            .await
            .unwrap()
    );
}

#[tokio::test]
#[ignore = "requires isolated real PostgreSQL TEST_DATABASE_URL; run serially"]
async fn simultaneous_workers_get_disjoint_live_leases() {
    let pool = database().await;
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    insert(&pool, a).await;
    insert(&pool, b).await;
    let (one, two) = tokio::join!(claim(&pool), claim(&pool));
    let one = one.unwrap().unwrap();
    let two = two.unwrap().unwrap();
    assert_ne!(one.id, two.id);
    assert_ne!(one.lease_token, two.lease_token);
    assert!(acknowledge(&pool, &one).await.unwrap());
    assert!(acknowledge(&pool, &two).await.unwrap());
    sqlx::query("DELETE FROM outbox_events WHERE aggregate_id=ANY($1)")
        .bind(vec![a.to_string(), b.to_string()])
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL, six-partition real Kafka topics, and signing/encryption env; run serially"]
async fn relay_publishes_canonical_key_trace_and_aggregate_order_to_real_kafka() {
    use rskafka::client::partition::{OffsetAt, UnknownTopicHandling};
    let mut config = identity_service::config::Config::from_env().unwrap();
    config.database_url = std::env::var("TEST_DATABASE_URL").unwrap();
    let state = identity_service::AppState::connect(config).await.unwrap();
    identity_service::migrate(&state.db).await.unwrap();
    let aggregate = Uuid::new_v4();
    let client = identity_service::adapters::kafka::client(&state.config)
        .await
        .unwrap();
    let partition = client
        .partition_client(
            "identity.events.v1",
            partition_for(aggregate),
            UnknownTopicHandling::Error,
        )
        .await
        .unwrap();
    let offset = partition.get_offset(OffsetAt::Latest).await.unwrap();
    let trace = "00-11111111111111111111111111111111-2222222222222222-01";
    let mut tx = state.db.begin().await.unwrap();
    let first = identity_service::events::enqueue(
        &mut tx,
        &state.crypto,
        "identity.email_verified",
        aggregate,
        serde_json::json!({"user_id":aggregate}),
        Some(trace),
    )
    .await
    .unwrap();
    let second = identity_service::events::enqueue(
        &mut tx,
        &state.crypto,
        "identity.password_changed",
        aggregate,
        serde_json::json!({"user_id":aggregate}),
        Some(trace),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let relay = tokio::spawn(identity_service::outbox::run(state.clone()));
    let records = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let mut next = offset;
        let mut observed = Vec::new();
        while observed.len() < 2 {
            let (records, _) = partition
                .fetch_records(next, 1..1_000_000, 1000)
                .await
                .unwrap();
            for record in records {
                next = record.offset + 1;
                if record.record.key.as_deref() != Some(aggregate.to_string().as_bytes()) {
                    continue;
                }
                let event: platform_contracts::Envelope =
                    serde_json::from_slice(record.record.value.as_ref().unwrap()).unwrap();
                assert_eq!(
                    record.record.headers.get("traceparent").unwrap(),
                    trace.as_bytes()
                );
                assert_eq!(event.traceparent.as_deref(), Some(trace));
                if observed.last() != Some(&event.event_id) {
                    observed.push(event.event_id);
                }
            }
        }
        observed
    })
    .await;
    relay.abort();
    let _ = relay.await;
    assert_eq!(records.unwrap(), vec![first, second]);
    sqlx::query("DELETE FROM outbox_events WHERE aggregate_id=$1")
        .bind(aggregate.to_string())
        .execute(&state.db)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires isolated real PostgreSQL TEST_DATABASE_URL; run serially"]
async fn sql_boundary_rejects_plaintext_delivery_commands() {
    let pool = database().await;
    let id = Uuid::new_v4();
    let aggregate = Uuid::new_v4();
    let plaintext = serde_json::json!({"schema_version":1,"event_id":id,"event_type":"notification.password_reset","aggregate_id":aggregate,"occurred_at":"2026-10-23T00:00:00Z","payload":{"user_id":aggregate,"email":"private@example.test","token":"must-not-persist","expires_at":"2026-10-23T01:00:00Z"}});
    let result = sqlx::query("INSERT INTO outbox_events(id,event_type,aggregate_id,topic,payload) VALUES($1,'notification.password_reset',$2,'notification.commands.v1',$3)").bind(id).bind(aggregate.to_string()).bind(plaintext).execute(&pool).await;
    assert!(result.is_err());
    assert!(!sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM outbox_events WHERE id=$1)"
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap());
}
