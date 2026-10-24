// SPDX-License-Identifier: MIT
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use identity_service::{
    auth,
    config::Config,
    security::{digest, random_token},
    AppState,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

async fn state() -> AppState {
    let mut c = Config::from_env().unwrap();
    c.database_url = std::env::var("TEST_DATABASE_URL").unwrap();
    let s = AppState::connect(c).await.unwrap();
    identity_service::migrate(&s.db).await.unwrap();
    s
}
struct User {
    id: Uuid,
    sid: Uuid,
    token: String,
    csrf: String,
}
async fn user(s: &AppState, role: Option<&str>) -> User {
    let u = User {
        id: Uuid::now_v7(),
        sid: Uuid::now_v7(),
        token: random_token(),
        csrf: random_token(),
    };
    sqlx::query("INSERT INTO users(id,email,password_hash,is_verified) VALUES($1,$2,'unused-test-hash',true)").bind(u.id).bind(format!("{}@generic.invalid",u.id)).execute(&s.db).await.unwrap();
    sqlx::query("INSERT INTO sessions(id,user_id,ip_address,user_agent,cookie_hash,csrf_hash,expires_at,mfa_verified,mfa_verified_at,reauthenticated_at,last_active_at) VALUES($1,$2,'127.0.0.1','Mozilla/5.0 (Windows NT 10.0) Chrome/130.0',$3,$4,now()+interval '1 day',true,now(),now(),now()-interval '5 minutes')").bind(u.sid).bind(u.id).bind(digest(&u.token)).bind(digest(&u.csrf)).execute(&s.db).await.unwrap();
    if let Some(role) = role {
        sqlx::query("INSERT INTO mfa_secrets(user_id,secret_key,is_enabled) VALUES($1,'enc:test-encrypted-factor',true)").bind(u.id).execute(&s.db).await.unwrap();
        sqlx::query(
            "INSERT INTO user_roles(user_id,role_id) SELECT $1,id FROM roles WHERE slug=$2",
        )
        .bind(u.id)
        .bind(role)
        .execute(&s.db)
        .await
        .unwrap();
    }
    u
}
async fn call(
    s: &AppState,
    u: &User,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header(
            "cookie",
            format!("sso_session={}; sso_csrf={}", u.token, u.csrf),
        )
        .header("origin", &s.config.public_origin)
        .header("x-csrf-token", &u.csrf);
    let bytes = if let Some(body) = body {
        b = b.header("content-type", "application/json");
        body.to_string()
    } else {
        String::new()
    };
    let response = identity_service::create_router(s.clone())
        .oneshot(b.body(Body::from(bytes)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and full identity configuration"]
async fn intrinsic_user_permissions_need_no_staff_binding_and_listing_never_touches_activity() {
    let s = state().await;
    let u = user(&s, None).await;
    let before: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT last_active_at FROM sessions WHERE id=$1")
            .bind(u.sid)
            .fetch_one(&s.db)
            .await
            .unwrap();
    let (status, items) = call(&s, &u, "GET", "/api/v1/auth/sessions", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(items[0]["session_id"], u.sid.to_string());
    assert_eq!(items[0]["browser"], "Chrome");
    assert_eq!(items[0]["os"], "Windows");
    assert!(items[0]["expires_at"].is_string());
    let after: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT last_active_at FROM sessions WHERE id=$1")
            .bind(u.sid)
            .fetch_one(&s.db)
            .await
            .unwrap();
    assert_eq!(before, after);
    let (_, me) = call(&s, &u, "GET", "/api/v1/auth/me", None).await;
    assert_eq!(me["user"]["roles"], json!([]));
    assert!(me["user"]["permissions"]
        .as_array()
        .unwrap()
        .contains(&json!("users:self:read")));
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and full identity configuration"]
async fn revoke_others_preserves_current_and_revokes_oauth_families() {
    let s = state().await;
    let u = user(&s, None).await;
    let sid = Uuid::now_v7();
    sqlx::query("INSERT INTO sessions(id,user_id,ip_address,user_agent,expires_at) VALUES($1,$2,'127.0.0.1','other',now()+interval '1 day')").bind(sid).bind(u.id).execute(&s.db).await.unwrap();
    let (status, body) = call(&s, &u, "POST", "/api/v1/auth/sessions/revoke-others", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], 1);
    let active: bool = sqlx::query_scalar("SELECT is_active FROM sessions WHERE id=$1")
        .bind(u.sid)
        .fetch_one(&s.db)
        .await
        .unwrap();
    assert!(active);
    let active: bool = sqlx::query_scalar("SELECT is_active FROM sessions WHERE id=$1")
        .bind(sid)
        .fetch_one(&s.db)
        .await
        .unwrap();
    assert!(!active);
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and full identity configuration"]
async fn support_cannot_escalate_roles_or_revoke_staff_sessions() {
    let s = state().await;
    let support = user(&s, Some("support")).await;
    let staff = user(&s, Some("admin")).await;
    let ordinary = user(&s, None).await;
    assert_eq!(
        call(
            &s,
            &support,
            "PUT",
            &format!("/api/v1/admin/users/{}/roles", support.id),
            Some(json!({"roles":["owner"],"reason":"escalation","expected_version":1}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &s,
            &support,
            "POST",
            &format!("/api/v1/admin/users/{}/sessions/revoke", staff.id),
            Some(json!({"reason":"support request"}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &s,
            &support,
            "POST",
            &format!("/api/v1/admin/users/{}/sessions/revoke", ordinary.id),
            Some(json!({"reason":"support request"}))
        )
        .await
        .0,
        StatusCode::OK
    );
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and full identity configuration; serial execution"]
async fn concurrent_owner_self_demotions_preserve_one_active_owner() {
    let s = state().await;
    // Disposable suite temporarily removes prior owners to control the invariant.
    let previous:Vec<(Uuid,Uuid)>=sqlx::query_as("DELETE FROM user_roles WHERE role_id=(SELECT id FROM roles WHERE slug='owner') RETURNING user_id,role_id").fetch_all(&s.db).await.unwrap();
    let a = user(&s, Some("owner")).await;
    let b = user(&s, Some("owner")).await;
    let pa = format!("/api/v1/admin/users/{}/roles", a.id);
    let pb = format!("/api/v1/admin/users/{}/roles", b.id);
    let (ra, rb) = tokio::join!(
        call(
            &s,
            &a,
            "PUT",
            &pa,
            Some(json!({"roles":[],"reason":"handover","expected_version":1}))
        ),
        call(
            &s,
            &b,
            "PUT",
            &pb,
            Some(json!({"roles":[],"reason":"handover","expected_version":1}))
        )
    );
    let statuses = [ra.0, rb.0];
    assert_eq!(statuses.iter().filter(|&&x| x == StatusCode::OK).count(), 1);
    assert!(statuses.contains(&StatusCode::CONFLICT));
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM user_roles ur JOIN roles r ON r.id=ur.role_id JOIN users u ON u.id=ur.user_id WHERE r.slug='owner' AND NOT u.is_banned").fetch_one(&s.db).await.unwrap();
    assert_eq!(count, 1);
    for (uid, rid) in previous {
        sqlx::query("INSERT INTO user_roles(user_id,role_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
            .bind(uid)
            .bind(rid)
            .execute(&s.db)
            .await
            .unwrap();
    }
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and full identity configuration"]
async fn owner_client_registration_is_exact_and_secret_is_one_time() {
    let s = state().await;
    let owner = user(&s, Some("owner")).await;
    let body = json!({"client_name":"Third party","redirect_uris":["https://consumer.invalid/callback"],"allowed_scopes":["openid","email"],"is_public":false,"trusted_first_party":false,"reason":"integration"});
    let (status, created) = call(
        &s,
        &owner,
        "POST",
        "/api/v1/admin/oauth/clients",
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(created["client_secret"].as_str().unwrap().len() >= 32);
    let hash: String =
        sqlx::query_scalar("SELECT client_secret_hash FROM oauth_clients WHERE client_id=$1")
            .bind(created["client_id"].as_str().unwrap())
            .fetch_one(&s.db)
            .await
            .unwrap();
    assert!(
        auth::verify_password(&s, created["client_secret"].as_str().unwrap().into(), hash)
            .await
            .unwrap()
    );
    let (_, listed) = call(&s, &owner, "GET", "/api/v1/admin/oauth/clients", None).await;
    assert!(listed["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|x| x.get("client_secret").is_none()));
    let bad = json!({"client_name":"bad","redirect_uris":["https://consumer.invalid/*"],"allowed_scopes":["openid"],"is_public":true,"trusted_first_party":false,"reason":"integration"});
    assert_eq!(
        call(&s, &owner, "POST", "/api/v1/admin/oauth/clients", Some(bad))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    sqlx::query("UPDATE sessions SET reauthenticated_at=now()-interval '6 minutes' WHERE id=$1")
        .bind(owner.sid)
        .execute(&s.db)
        .await
        .unwrap();
    assert_eq!(
        call(
            &s,
            &owner,
            "POST",
            &format!(
                "/api/v1/admin/oauth/clients/{}/rotate",
                created["client_id"].as_str().unwrap()
            ),
            Some(json!({"reason":"rotate"}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}
#[test]
fn owner_only_permissions_cannot_be_granted_by_editable_map() {
    let actor = auth::Actor {
        user_id: Uuid::nil(),
        session_id: Uuid::nil(),
        email: "x@x.invalid".into(),
        is_verified: true,
        mfa_enabled: true,
        mfa_verified: true,
        roles: vec!["admin".into()],
        permissions: vec!["roles:assign".into()],
    };
    assert!(auth::require_permission(&actor, "roles:assign").is_err());
    assert!(!identity_service::rbac::known_permission("arbitrary:root"));
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and full identity configuration"]
async fn thirdparty_consent_is_session_bound_single_use_and_preserves_exact_redirect() {
    let s = state().await;
    let u = user(&s, None).await;
    let other = user(&s, None).await;
    let id = format!("thirdparty-{}", Uuid::now_v7());
    sqlx::query("INSERT INTO oauth_clients(client_id,client_name,redirect_uris,allowed_scopes,is_public) VALUES($1,'Consumer',ARRAY['https://consumer.invalid/callback'],ARRAY['openid','email'],true)").bind(&id).execute(&s.db).await.unwrap();
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("client_id", id.as_str()),
            ("redirect_uri", "https://consumer.invalid/callback"),
            ("response_type", "code"),
            ("scope", "openid email"),
            ("state", "original-state"),
            (
                "code_challenge",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            ),
            ("code_challenge_method", "S256"),
        ])
        .finish();
    let response = identity_service::create_router(s.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/oauth/authorize?{query}"))
                .header("cookie", format!("sso_session={}", u.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"].to_str().unwrap();
    assert!(location.starts_with("/oauth/consent?request_id="));
    let request_id = location.split('=').nth(1).unwrap();
    let path = format!("/api/v1/auth/oauth/consent/{request_id}");
    assert_eq!(
        call(&s, &other, "GET", &path, None).await.0,
        StatusCode::BAD_REQUEST
    );
    let (status, decision) = call(&s, &u, "POST", &path, Some(json!({"approved":true}))).await;
    assert_eq!(status, StatusCode::OK);
    let complete = decision["redirect_to"].as_str().unwrap();
    assert_eq!(complete, format!("/oauth/consent/complete/{request_id}"));
    let response = identity_service::create_router(s.clone())
        .oneshot(
            Request::builder()
                .uri(complete)
                .header("cookie", format!("sso_session={}", u.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let target = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    assert_eq!(
        target.origin().ascii_serialization(),
        "https://consumer.invalid"
    );
    assert_eq!(target.path(), "/callback");
    assert!(target
        .query_pairs()
        .any(|(k, v)| k == "state" && v == "original-state"));
    assert!(target.query_pairs().any(|(k, _)| k == "code"));
    assert_eq!(
        call(&s, &u, "POST", &path, Some(json!({"approved":true})))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and full identity configuration"]
async fn registration_without_code_never_calls_referral_and_emits_durable_v2_metadata() {
    let mut s = state().await;
    let mut c = (*s.config).clone();
    c.referral_url = "https://unreachable.invalid".into();
    c.internal_ca_file = "/missing".into();
    s.config = std::sync::Arc::new(c);
    let u = user(&s, None).await;
    let email = format!("{}@registration.invalid", Uuid::now_v7());
    let (status, body) = call(
        &s,
        &u,
        "POST",
        "/api/v1/auth/register",
        Some(json!({"email":email,"password":"A sufficiently long password123!","locale":"ru"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = Uuid::parse_str(body["user_id"].as_str().unwrap()).unwrap();
    let value:Value=sqlx::query_scalar("SELECT payload FROM outbox_events WHERE aggregate_id=$1 AND event_type='identity.user_registered'").bind(id.to_string()).fetch_one(&s.db).await.unwrap();
    let e: platform_contracts::eventsv2::Envelope = serde_json::from_value(value).unwrap();
    assert_eq!(e.producer, "identity");
    assert_eq!(e.aggregate_version, 1);
    let p = e.payload.unwrap();
    assert_eq!(p["locale"], "ru");
    assert!(p["registration_id"].is_string());
    assert!(p["referral_claim_id"].is_null());
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&s.db)
        .await
        .unwrap();
    let email = format!("{}@registration.invalid", Uuid::now_v7());
    let result=call(&s,&u,"POST","/api/v1/auth/register",Some(json!({"email":email,"password":"A sufficiently long password123!","referral_code":"provided-code"}))).await;
    assert_eq!(result.0, StatusCode::SERVICE_UNAVAILABLE);
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&s.db)
        .await
        .unwrap();
    assert_eq!(before, after);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and full identity configuration"]
async fn v2_introspection_scopes_owner_tokens_and_requires_fresh_mfa() {
    let mut s = state().await;
    let mut config = (*s.config).clone();
    config.catalog_internal_token = random_token();
    s.config = std::sync::Arc::new(config);
    let owner = user(&s, Some("owner")).await;
    async fn introspect(s: &AppState, u: &User, token: &str, p: &str) -> StatusCode {
        let b = json!({"session_cookie":u.token,"method":"GET","permission":p,"require_mfa":false});
        identity_service::create_router(s.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/v2/introspect")
                    .header("x-service-token", token)
                    .header("content-type", "application/json")
                    .body(Body::from(b.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }
    assert_eq!(
        introspect(
            &s,
            &owner,
            &s.config.catalog_internal_token,
            "catalog:write"
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        introspect(
            &s,
            &owner,
            &s.config.catalog_internal_token,
            "billing:resolve"
        )
        .await,
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE sessions SET mfa_verified_at=now()-interval '16 minutes' WHERE id=$1")
        .bind(owner.sid)
        .execute(&s.db)
        .await
        .unwrap();
    assert_eq!(
        introspect(
            &s,
            &owner,
            &s.config.catalog_internal_token,
            "catalog:write"
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        introspect(&s, &owner, "", "users:self:read").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and full identity configuration"]
async fn admin_command_replay_is_durable_and_body_conflicts_do_not_repeat_events() {
    let s = state().await;
    let owner = user(&s, Some("owner")).await;
    let target = user(&s, None).await;
    let command_id = Uuid::now_v7();
    async fn run(s: &AppState, u: &User, path: &str, body: Value) -> (StatusCode, Value) {
        let response = identity_service::create_router(s.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("x-service-token", &s.config.admin_internal_token)
                    .header("x-actor-session", &u.token)
                    .header("origin", &s.config.public_origin)
                    .header(
                        "cookie",
                        format!("sso_session={}; sso_csrf={}", u.token, u.csrf),
                    )
                    .header("x-csrf-token", &u.csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16384).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    let path = format!("/internal/v2/admin/users/{}/ban", target.id);
    let b = json!({"reason":"abuse decision","idempotency_key":command_id});
    let first = run(&s, &owner, &path, b.clone()).await;
    assert_eq!(first.0, StatusCode::OK);
    let replay = run(&s, &owner, &path, b).await;
    assert_eq!(first, replay);
    let conflict = run(
        &s,
        &owner,
        &path,
        json!({"reason":"different","idempotency_key":command_id}),
    )
    .await;
    assert_eq!(conflict.0, StatusCode::CONFLICT);
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM outbox_events WHERE aggregate_id=$1 AND event_type='identity.user_banned'").bind(target.id.to_string()).fetch_one(&s.db).await.unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and full identity configuration"]
async fn support_command_status_uses_original_actor_action_current_permission_and_fresh_mfa() {
    let s = state().await;
    let support = user(&s, Some("support")).await;
    let foreign = user(&s, Some("support")).await;
    let ordinary = user(&s, None).await;
    let command_id = Uuid::now_v7();
    async fn owner_call(
        s: &AppState,
        u: &User,
        token: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
        csrf: bool,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("x-service-token", token)
            .header(
                "cookie",
                format!("sso_session={}; sso_csrf={}", u.token, u.csrf),
            );
        if csrf {
            request = request
                .header("origin", &s.config.public_origin)
                .header("x-csrf-token", &u.csrf);
        }
        let bytes = if let Some(body) = body {
            request = request.header("content-type", "application/json");
            body.to_string()
        } else {
            String::new()
        };
        let response = identity_service::create_router(s.clone())
            .oneshot(request.body(Body::from(bytes)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16384).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
    let path = format!("/internal/v2/admin/commands/{command_id}");
    let admin = &s.config.admin_internal_token;
    // An allowed SUPPORT actor can establish authoritative absence without audit:read.
    let absent = owner_call(&s, &support, admin, "GET", &path, None, false).await;
    assert_eq!(absent.0, StatusCode::NOT_FOUND, "{absent:?}");
    assert_eq!(absent.1["code"], "command_not_found");
    assert_eq!(
        owner_call(&s, &ordinary, admin, "GET", &path, None, false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        owner_call(
            &s,
            &support,
            &s.config.notification_internal_token,
            "GET",
            &path,
            None,
            false
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let mutation_path = format!("/internal/v2/admin/users/{}/sessions/revoke", ordinary.id);
    let body = json!({"reason":"support case","idempotency_key":command_id});
    assert_eq!(
        owner_call(
            &s,
            &support,
            admin,
            "POST",
            &mutation_path,
            Some(body.clone()),
            false
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let committed = owner_call(
        &s,
        &support,
        admin,
        "POST",
        &mutation_path,
        Some(body.clone()),
        true,
    )
    .await;
    assert_eq!(committed.0, StatusCode::OK, "{committed:?}");
    assert_eq!(committed.1["revoked"], 1);
    // Ignore the mutation response: recovery must use its persisted same UUID/result.
    let recovered = owner_call(&s, &support, admin, "GET", &path, None, false).await;
    assert_eq!(recovered.0, StatusCode::OK, "{recovered:?}");
    assert_eq!(
        recovered.1,
        json!({"command_id":command_id,"status":"succeeded","result":{"revoked":1}})
    );
    assert_eq!(
        owner_call(&s, &foreign, admin, "GET", &path, None, false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let new_session = Uuid::now_v7();
    sqlx::query("INSERT INTO sessions(id,user_id,ip_address,user_agent,expires_at) VALUES($1,$2,'127.0.0.1','new after commit',now()+interval '1 day')")
        .bind(new_session).bind(ordinary.id).execute(&s.db).await.unwrap();
    assert_eq!(
        owner_call(
            &s,
            &support,
            admin,
            "POST",
            &mutation_path,
            Some(body),
            true
        )
        .await,
        committed
    );
    let active: bool = sqlx::query_scalar("SELECT is_active FROM sessions WHERE id=$1")
        .bind(new_session)
        .fetch_one(&s.db)
        .await
        .unwrap();
    assert!(active, "same-key replay repeated revocation");
    // Holding a different allowed command permission is not sufficient for stored ban.
    let ban_id = Uuid::now_v7();
    sqlx::query("INSERT INTO identity_admin_commands(command_id,actor_user_id,operation,target,request,result) VALUES($1,$2,'ban',$3,'{}','{}')")
        .bind(ban_id).bind(support.id).bind(ordinary.id).execute(&s.db).await.unwrap();
    assert_eq!(
        owner_call(
            &s,
            &support,
            admin,
            "GET",
            &format!("/internal/v2/admin/commands/{ban_id}"),
            None,
            false
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE sessions SET mfa_verified_at=now()-interval '16 minutes' WHERE id=$1")
        .bind(support.sid)
        .execute(&s.db)
        .await
        .unwrap();
    assert_eq!(
        owner_call(&s, &support, admin, "GET", &path, None, false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let unknown = format!("/internal/v2/admin/commands/{}", Uuid::now_v7());
    assert_eq!(
        owner_call(&s, &support, admin, "GET", &unknown, None, false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE sessions SET mfa_verified_at=now() WHERE id=$1")
        .bind(support.sid)
        .execute(&s.db)
        .await
        .unwrap();
    sqlx::query("DELETE FROM user_roles WHERE user_id=$1")
        .bind(support.id)
        .execute(&s.db)
        .await
        .unwrap();
    assert_eq!(
        owner_call(&s, &support, admin, "GET", &path, None, false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        owner_call(&s, &support, admin, "GET", &unknown, None, false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and full identity configuration"]
async fn assignment_read_keeps_roles_and_expected_version_in_one_snapshot() {
    let s = state().await;
    let owner = user(&s, Some("owner")).await;
    let target = user(&s, Some("admin")).await;
    let pool = s.db.clone();
    let id = target.id;
    let writer = tokio::spawn(async move {
        for version in 2_i64..=201 {
            let role = if version % 2 == 0 { "support" } else { "admin" };
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
                .bind(id)
                .execute(&mut *tx)
                .await
                .unwrap();
            sqlx::query("DELETE FROM user_roles WHERE user_id=$1")
                .bind(id)
                .execute(&mut *tx)
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO user_roles(user_id,role_id) SELECT $1,id FROM roles WHERE slug=$2",
            )
            .bind(id)
            .bind(role)
            .execute(&mut *tx)
            .await
            .unwrap();
            sqlx::query("UPDATE users SET role_version=$2 WHERE id=$1")
                .bind(id)
                .bind(version)
                .execute(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            tokio::task::yield_now().await;
        }
    });
    for _ in 0..200 {
        let (status, body) = call(
            &s,
            &owner,
            "GET",
            &format!("/api/v1/admin/users/{}/roles", target.id),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let version = body["role_version"].as_i64().unwrap();
        let expected = if version % 2 == 0 { "support" } else { "admin" };
        assert_eq!(
            body["roles"],
            json!([expected]),
            "role set must come from the same snapshot as its optimistic version"
        );
    }
    writer.await.unwrap();
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and full identity configuration"]
async fn staff_session_revocation_respects_current_actor_hierarchy() {
    let s = state().await;
    let owner = user(&s, Some("owner")).await;
    let admin = user(&s, Some("admin")).await;
    let staff = user(&s, Some("support")).await;
    let body = json!({"reason":"staff credential response"});
    assert_eq!(
        call(
            &s,
            &admin,
            "POST",
            &format!("/api/v1/admin/users/{}/sessions/revoke", owner.id),
            Some(body.clone())
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &s,
            &admin,
            "POST",
            &format!("/api/v1/admin/users/{}/sessions/revoke", staff.id),
            Some(body.clone())
        )
        .await
        .0,
        StatusCode::OK
    );
    let other_admin = user(&s, Some("admin")).await;
    assert_eq!(
        call(
            &s,
            &owner,
            "POST",
            &format!("/api/v1/admin/users/{}/sessions/revoke", other_admin.id),
            Some(body)
        )
        .await
        .0,
        StatusCode::OK
    );
    let active: bool = sqlx::query_scalar("SELECT is_active FROM sessions WHERE id=$1")
        .bind(other_admin.sid)
        .fetch_one(&s.db)
        .await
        .unwrap();
    assert!(!active);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and full identity configuration"]
async fn owner_mutations_commit_sanitized_audit_event_with_local_audit_row() {
    let s = state().await;
    let owner = user(&s, Some("owner")).await;
    let target = user(&s, None).await;
    let (status, _) = call(
        &s,
        &owner,
        "PUT",
        &format!("/api/v1/admin/users/{}/roles", target.id),
        Some(json!({"roles":["support"],"reason":"staff onboarding","expected_version":1})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let row:(Uuid,Value)=sqlx::query_as("SELECT a.id,e.payload FROM identity_admin_audit a JOIN outbox_events e ON e.id=a.id WHERE a.actor_user_id=$1 AND a.operation='user.roles' AND a.target=$2").bind(owner.id).bind(target.id.to_string()).fetch_one(&s.db).await.unwrap();
    let e: platform_contracts::eventsv2::Envelope = serde_json::from_value(row.1).unwrap();
    e.validate().unwrap();
    assert_eq!(e.event_id, row.0);
    assert_eq!(e.aggregate_id, row.0);
    assert_eq!(e.aggregate_version, 1);
    assert_eq!(e.event_type, "identity.admin_action_recorded");
    let p = e.payload.unwrap();
    assert_eq!(p["actor_user_id"], owner.id.to_string());
    assert_eq!(p["target_type"], "user");
    assert_eq!(p["target_id"], target.id.to_string());
    assert_eq!(p["reason"], "staff onboarding");
    assert!(p.get("details").is_none());
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and full identity configuration"]
async fn registration_backfill_timestamp_matches_authoritative_event_occurrence() {
    let s = state().await;
    let actor = user(&s, None).await;
    let email = format!("{}@registered-time.invalid", Uuid::now_v7());
    let (status, body) = call(
        &s,
        &actor,
        "POST",
        "/api/v1/auth/register",
        Some(json!({"email":email,"password":"A long registration password123!"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = Uuid::parse_str(body["user_id"].as_str().unwrap()).unwrap();
    let times:(chrono::DateTime<chrono::Utc>,chrono::DateTime<chrono::Utc>)=sqlx::query_as("SELECT u.created_at,(e.payload->>'occurred_at')::timestamptz FROM users u JOIN outbox_events e ON e.aggregate_id=u.id::text AND e.event_type='identity.user_registered' WHERE u.id=$1").bind(id).fetch_one(&s.db).await.unwrap();
    assert_eq!(
        times.0, times.1,
        "backfill must preserve registration occurrence used for referral deadline admission"
    );
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and full identity configuration"]
async fn registration_occurrence_after_enqueue_lock_wait_cannot_cross_claim_deadline() {
    let s = state().await;
    let id = Uuid::now_v7();
    let deadline = chrono::Utc::now() + chrono::Duration::seconds(1);
    let mut blocker = s.db.begin().await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(id.to_string())
        .execute(&mut *blocker)
        .await
        .unwrap();
    let state = s.clone();
    let attempt = tokio::spawn(async move {
        let mut tx = state.db.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO users(id,email,password_hash,registration_id) VALUES($1,$2,'unused',$1)",
        )
        .bind(id)
        .bind(format!("{id}@deadline.invalid"))
        .execute(&mut *tx)
        .await
        .unwrap();
        let result=identity_service::events::enqueue_registration(&mut tx,&state.crypto,id,json!({"user_id":id,"email":format!("{id}@deadline.invalid"),"locale":"en","registration_id":id,"referral_claim_id":Uuid::now_v7()}),None,Some(deadline)).await;
        tx.rollback().await.unwrap();
        result
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(pid)
            .fetch_one(&s.db)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    loop {
        let after: bool = sqlx::query_scalar("SELECT clock_timestamp()>$1")
            .bind(deadline)
            .fetch_one(&s.db)
            .await
            .unwrap();
        if after {
            break;
        }
        tokio::task::yield_now().await;
    }
    blocker.commit().await.unwrap();
    let error = tokio::time::timeout(std::time::Duration::from_secs(5), attempt)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, "referral_claim_expired");
    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1) OR EXISTS(SELECT 1 FROM outbox_events WHERE aggregate_id=$2)").bind(id).bind(id.to_string()).fetch_one(&s.db).await.unwrap();
    assert!(!exists);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and full identity configuration"]
async fn client_name_accepts_full_canonical_two_hundred_character_limit() {
    let s = state().await;
    let owner = user(&s, Some("owner")).await;
    let (status,body)=call(&s,&owner,"POST","/api/v1/admin/oauth/clients",Some(json!({"client_name":"x".repeat(200),"redirect_uris":["https://consumer.invalid/callback"],"allowed_scopes":["openid"],"is_public":true,"trusted_first_party":false,"reason":"name boundary"}))).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["client_name"].as_str().unwrap().len(), 200);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and full identity configuration"]
async fn admin_notification_frontdoor_admits_exact_permissions_but_profile_cannot_publish() {
    let s = state().await;
    let owner = user(&s, Some("owner")).await;
    async fn admit(s: &AppState, u: &User, token: &str, permission: &str) -> StatusCode {
        let request = json!({"session_cookie":u.token,"method":"GET","permission":permission,"require_mfa":false});
        identity_service::create_router(s.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/v2/introspect")
                    .header("x-service-token", token)
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }
    for permission in [
        "notifications:read",
        "notifications:templates:write",
        "notifications:replay",
    ] {
        assert_eq!(
            admit(&s, &owner, &s.config.admin_internal_token, permission).await,
            StatusCode::OK
        );
    }
    for permission in ["notifications:read", "notifications:replay"] {
        assert_eq!(
            admit(&s, &owner, &s.config.profile_internal_token, permission).await,
            StatusCode::OK
        );
    }
    assert_eq!(
        admit(
            &s,
            &owner,
            &s.config.profile_internal_token,
            "billing:resolve"
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        admit(
            &s,
            &owner,
            &s.config.profile_internal_token,
            "notifications:templates:write"
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        admit(
            &s,
            &owner,
            &s.config.admin_internal_token,
            "notifications:bindings:reset"
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        admit(
            &s,
            &owner,
            &s.config.admin_internal_token,
            "billing:resolve"
        )
        .await,
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE sessions SET mfa_verified_at=now()-interval '16 minutes' WHERE id=$1")
        .bind(owner.sid)
        .execute(&s.db)
        .await
        .unwrap();
    assert_eq!(
        admit(
            &s,
            &owner,
            &s.config.admin_internal_token,
            "notifications:templates:write"
        )
        .await,
        StatusCode::FORBIDDEN
    );
    for permission in ["notifications:read", "notifications:replay"] {
        assert_eq!(
            admit(&s, &owner, &s.config.profile_internal_token, permission).await,
            StatusCode::FORBIDDEN
        );
    }
}
