use identity_service::{auth, config::Config, AppState};
use sqlx::{postgres::PgPoolOptions, Row};
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("TLS crypto provider initialization failed"))?;
    dotenvy::dotenv().ok();
    let telemetry = identity_service::telemetry::init_telemetry()?;
    let command = std::env::args().nth(1).unwrap_or_else(|| "serve".into());
    if command == "rekey" {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL")?)
            .await?;
        identity_service::rekey::run(
            &pool,
            identity_service::rekey::key_from_env("LEGACY_ENCRYPTION_KEY")?,
            identity_service::rekey::key_from_env("MFA_ENCRYPTION_KEY")?,
            identity_service::rekey::key_from_env("DELIVERY_ENCRYPTION_KEY")?,
        )
        .await?;
        tracing::info!("identity purpose-key migration completed");
        return Ok(());
    }
    if command == "migrate" {
        let db = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL")?)
            .await?;
        identity_service::migrate(&db).await?;
        tracing::info!("identity migrations applied");
        return Ok(());
    }
    if command != "serve" && command != "bootstrap-admin" {
        anyhow::bail!("usage: identity-service [serve|migrate|rekey|bootstrap-admin]");
    }
    let config = Config::from_env()?;
    let state = AppState::connect(config).await?;
    if command == "bootstrap-admin" {
        bootstrap_admin(&state).await?;
        return Ok(());
    }
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        &state.config.tls_cert_file,
        &state.config.tls_key_file,
    )
    .await?;
    let address = std::net::SocketAddr::from(([0, 0, 0, 0], state.config.http_port));
    let relay = tokio::spawn(identity_service::outbox::run(state.clone()));
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(15)));
    });
    tracing::info!(
        port = state.config.http_port,
        "identity HTTPS listener starting"
    );
    axum_server::bind_rustls(address, tls)
        .handle(handle)
        .serve(
            identity_service::create_router(state.clone())
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await?;
    relay.abort();
    state.db.close().await;
    if let Some(provider) = telemetry {
        let _ = provider.shutdown();
    }
    Ok(())
}
async fn bootstrap_admin(state: &AppState) -> anyhow::Result<()> {
    let email = std::env::var("ADMIN_EMAIL")?.trim().to_lowercase();
    if email.len() > 254 || !email.contains('@') {
        anyhow::bail!("invalid ADMIN_EMAIL");
    }
    let password = std::env::var("ADMIN_PASSWORD")?;
    let hash = auth::hash_password(state, password)
        .await
        .map_err(|_| anyhow::anyhow!("ADMIN_PASSWORD must contain 12..1024 bytes"))?;
    let mut tx = state.db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(742915830)")
        .execute(&mut *tx)
        .await?;
    let existing=sqlx::query("SELECT u.id,EXISTS(SELECT 1 FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=u.id AND r.slug='admin') administrator FROM users u WHERE u.email=$1 FOR UPDATE").bind(&email).fetch_optional(&mut *tx).await?;
    if let Some(row) = existing {
        if row.get::<bool, _>("administrator") {
            tx.commit().await?;
            tracing::info!("bootstrap administrator already exists; password unchanged");
            return Ok(());
        }
        anyhow::bail!(
            "ADMIN_EMAIL already belongs to a non-bootstrap account; refusing privilege escalation"
        );
    }
    let uid = Uuid::now_v7();
    sqlx::query("INSERT INTO users(id,email,password_hash,is_verified) VALUES($1,$2,$3,true)")
        .bind(uid)
        .bind(&email)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO user_roles(user_id,role_id) SELECT $1,id FROM roles WHERE slug IN ('user','admin')").bind(uid).execute(&mut *tx).await?;
    identity_service::events::enqueue(
        &mut tx,
        &state.crypto,
        "identity.user_registered",
        uid,
        serde_json::json!({"user_id":uid,"email":email}),
        None,
    )
    .await
    .map_err(|_| anyhow::anyhow!("bootstrap outbox failed"))?;
    tx.commit().await?;
    tracing::info!("bootstrap administrator created; MFA enrollment and MFA login required for administrative privileges");
    Ok(())
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM registration");
        tokio::select! {_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{}}
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
