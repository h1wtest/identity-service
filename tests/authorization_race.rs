use identity_service::{
    auth,
    config::Config,
    security::{digest, random_token},
    AppState,
};
use sqlx::Row;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires real disposable TEST_DATABASE_URL and full identity configuration"]
async fn revoked_session_waiting_behind_user_lock_cannot_change_password() {
    let mut config = Config::from_env().unwrap();
    config.database_url = std::env::var("TEST_DATABASE_URL").unwrap();
    let state = AppState::connect(config).await.unwrap();
    identity_service::migrate(&state.db).await.unwrap();
    let uid = Uuid::new_v4();
    let sid = Uuid::new_v4();
    let token = random_token();
    let original = auth::hash_password(&state, "Correct Original Password!123".into())
        .await
        .unwrap();
    let replacement = auth::hash_password(&state, "Correct Replacement Password!456".into())
        .await
        .unwrap();
    sqlx::query("INSERT INTO users(id,email,password_hash,is_verified) VALUES($1,$2,$3,true)")
        .bind(uid)
        .bind(format!("{uid}@race.invalid"))
        .bind(&original)
        .execute(&state.db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO sessions(id,user_id,ip_address,user_agent,cookie_hash,expires_at,reauthenticated_at) VALUES($1,$2,'127.0.0.1','race',$3,now()+interval '1 day',now())").bind(sid).bind(uid).bind(digest(&token)).execute(&state.db).await.unwrap();
    let mut blocker = state.db.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(uid)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let pool = state.db.clone();
    let expected = original.clone();
    let updated = replacement.clone();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let attempt = tokio::spawn(async move {
        let mut tx = pool.begin().await.unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        sender.send(pid).unwrap();
        let result = identity_service::application::security::change_password(
            &mut identity_service::adapters::postgres::security::PostgresSecurityTransaction {
                transaction: &mut tx,
            },
            uid,
            sid,
            &expected,
            &updated,
        )
        .await;
        let _ = tx.rollback().await;
        result
    });
    let pid = receiver.await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5),async{loop{let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')").bind(pid).fetch_one(&state.db).await.unwrap();if waiting{break;}tokio::task::yield_now().await;}}).await.unwrap();
    sqlx::query("UPDATE sessions SET is_active=false WHERE id=$1")
        .bind(sid)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    let failure = attempt.await.unwrap().unwrap_err();
    assert_eq!(failure.status, axum::http::StatusCode::UNAUTHORIZED);
    let row = sqlx::query("SELECT password_hash FROM users WHERE id=$1")
        .bind(uid)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("password_hash"), original);
}
