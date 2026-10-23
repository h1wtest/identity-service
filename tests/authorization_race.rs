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

async fn revoked_actor_cannot_revoke_after_waiting(revoke_all: bool) {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    let mut config = Config::from_env().unwrap();
    config.database_url = std::env::var("TEST_DATABASE_URL").unwrap();
    let state = AppState::connect(config).await.unwrap();
    identity_service::migrate(&state.db).await.unwrap();
    let uid = Uuid::new_v4();
    let actor_sid = Uuid::new_v4();
    let target_sid = Uuid::new_v4();
    let token = random_token();
    let csrf = random_token();
    sqlx::query("INSERT INTO users(id,email,password_hash,is_verified) VALUES($1,$2,'unused-race-password',true)")
        .bind(uid).bind(format!("{uid}@revocation-race.invalid")).execute(&state.db).await.unwrap();
    sqlx::query("INSERT INTO sessions(id,user_id,ip_address,user_agent,cookie_hash,csrf_hash,expires_at) VALUES($1,$2,'127.0.0.1','actor-race',$3,$4,now()+interval '1 day')")
        .bind(actor_sid).bind(uid).bind(digest(&token)).bind(digest(&csrf)).execute(&state.db).await.unwrap();
    if !revoke_all {
        sqlx::query("INSERT INTO sessions(id,user_id,ip_address,user_agent,cookie_hash,expires_at) VALUES($1,$2,'127.0.0.1','target-race',$3,now()+interval '1 day')")
            .bind(target_sid).bind(uid).bind(digest(&random_token())).execute(&state.db).await.unwrap();
    }

    let mut blocker = state.db.begin().await.unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(uid)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let path = if revoke_all {
        "/api/v1/auth/sessions".to_owned()
    } else {
        format!("/api/v1/auth/sessions/{target_sid}")
    };
    let request = Request::builder()
        .method("DELETE")
        .uri(path)
        .header("origin", &state.config.public_origin)
        .header("cookie", format!("sso_session={token}; sso_csrf={csrf}"))
        .header("x-csrf-token", &csrf)
        .body(Body::empty())
        .unwrap();
    let app = identity_service::create_router(state.clone());
    let attempt = tokio::spawn(async move { app.oneshot(request).await.unwrap() });
    // The database lock graph proves the HTTP request passed initial authentication
    // and reached the mutation transaction; no elapsed-time guess controls this race.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(blocker_pid)
            .fetch_one(&state.db)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("revocation request must wait for the locked user");
    sqlx::query("UPDATE sessions SET is_active=false WHERE id=$1")
        .bind(actor_sid)
        .execute(&mut *blocker)
        .await
        .unwrap();
    if revoke_all {
        sqlx::query("INSERT INTO sessions(id,user_id,ip_address,user_agent,cookie_hash,expires_at) VALUES($1,$2,'127.0.0.1','replacement-race',$3,now()+interval '1 day')")
            .bind(target_sid).bind(uid).bind(digest(&random_token())).execute(&mut *blocker).await.unwrap();
    }
    blocker.commit().await.unwrap();
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), attempt)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let target_active: bool = sqlx::query_scalar("SELECT is_active FROM sessions WHERE id=$1")
        .bind(target_sid)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert!(
        target_active,
        "revoked actor must not revoke the target session"
    );
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox_events WHERE aggregate_id=$1 AND event_type='identity.session_revoked'")
        .bind(uid.to_string()).fetch_one(&state.db).await.unwrap();
    assert_eq!(
        events, 0,
        "denied revocation must not enqueue a mutation event"
    );
}

#[tokio::test]
#[ignore = "requires real disposable TEST_DATABASE_URL and full identity configuration"]
async fn revoked_actor_waiting_to_revoke_all_cannot_revoke_replacement_session() {
    revoked_actor_cannot_revoke_after_waiting(true).await;
}

#[tokio::test]
#[ignore = "requires real disposable TEST_DATABASE_URL and full identity configuration"]
async fn revoked_actor_waiting_to_revoke_one_cannot_revoke_target_session() {
    revoked_actor_cannot_revoke_after_waiting(false).await;
}
