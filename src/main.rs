use std::net::SocketAddr;
use std::sync::Arc;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info};

mod adapters;
mod application;
mod config;
mod domain;
mod proto;
mod telemetry;

use adapters::inbound::grpc::GrpcIdentityService;
use adapters::inbound::http::{create_router, AppState};
use adapters::outbound::crypto::DefaultCryptoService;
use adapters::outbound::kafka::outbox_relay::OutboxRelayWorker;
use adapters::outbound::postgres::mfa_repo::PostgresMfaRepository;
use adapters::outbound::postgres::outbox_repo::PostgresOutboxRepository;
use adapters::outbound::postgres::rbac_repo::PostgresRbacRepository;
use adapters::outbound::postgres::session_repo::PostgresSessionMetadataRepository;
use adapters::outbound::postgres::user_repo::PostgresUserRepository;
use adapters::outbound::postgres::oauth_repo::PostgresOAuthClientRepository;
use adapters::outbound::redis::oauth_code_store::RedisOAuthCodeStore;
use adapters::outbound::redis::session_store::RedisSessionStore;
use application::oauth::OAuthUseCase;
use application::login::LoginUseCase;
use application::mfa::MfaUseCase;
use application::register::RegisterUseCase;
use application::sessions::SessionsUseCase;
use config::Config;
use proto::identity::v1::identity_service_server::IdentityServiceServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    telemetry::init_telemetry();

    info!("Starting identity-service...");

    let config = Config::from_env()?;

    // 1. Database Connection Pool
    info!("Connecting to PostgreSQL database...");
    let db_pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&config.database_url)
        .await?;
    info!("PostgreSQL connection established successfully");

    // 2. Redis Connection
    info!("Connecting to Redis...");
    let session_store = Arc::new(RedisSessionStore::new(&config.redis_url).await?);
    info!("Redis connection established successfully");

    // 3. Cryptography & Security
    let crypto = Arc::new(DefaultCryptoService::new(
        config.jwt_secret.clone(),
        config.access_token_ttl_seconds,
        config.refresh_token_ttl_seconds,
    ));

    // 4. Repositories
    let user_repo = Arc::new(PostgresUserRepository::new(db_pool.clone()));
    let rbac_repo = Arc::new(PostgresRbacRepository::new(db_pool.clone()));
    let session_metadata_repo = Arc::new(PostgresSessionMetadataRepository::new(db_pool.clone()));
    let mfa_repo = Arc::new(PostgresMfaRepository::new(db_pool.clone()));
    let outbox_repo = Arc::new(PostgresOutboxRepository::new(db_pool.clone()));
    let client_repo = Arc::new(PostgresOAuthClientRepository::new(db_pool.clone()));
    let code_store = Arc::new(RedisOAuthCodeStore::new(session_store.manager()));

    // 5. Application Use Cases
    let register_use_case = Arc::new(RegisterUseCase::new(
        user_repo.clone(),
        rbac_repo.clone(),
        outbox_repo.clone(),
        crypto.clone(),
    ));

    let login_use_case = Arc::new(LoginUseCase::new(
        user_repo.clone(),
        rbac_repo.clone(),
        mfa_repo.clone(),
        session_store.clone(),
        session_metadata_repo.clone(),
        outbox_repo.clone(),
        crypto.clone(),
        config.refresh_token_ttl_seconds,
    ));

    let mfa_use_case = Arc::new(MfaUseCase::new(
        user_repo.clone(),
        rbac_repo.clone(),
        mfa_repo.clone(),
        session_store.clone(),
        session_metadata_repo.clone(),
        outbox_repo.clone(),
        crypto.clone(),
        config.refresh_token_ttl_seconds,
    ));

    let sessions_use_case = Arc::new(SessionsUseCase::new(
        session_store.clone(),
        session_metadata_repo.clone(),
        outbox_repo.clone(),
    ));

    let oauth_use_case = Arc::new(OAuthUseCase::new(
        client_repo.clone(),
        code_store.clone(),
        user_repo.clone(),
        rbac_repo.clone(),
        session_store.clone(),
        session_metadata_repo.clone(),
        crypto.clone(),
        config.oauth_issuer.clone(),
        config.refresh_token_ttl_seconds,
    ));

    // 6. Background Outbox Relay to Kafka
    let outbox_worker_repo = outbox_repo.clone();
    let kafka_brokers = config.kafka_brokers.clone();
    let kafka_topic = config.kafka_identity_topic.clone();

    tokio::spawn(async move {
        match OutboxRelayWorker::new(outbox_worker_repo, kafka_brokers, &kafka_topic).await {
            Ok(worker) => {
                info!("Outbox Relay worker successfully initialized");
                worker.run().await;
            }
            Err(e) => {
                error!("Failed to initialize Outbox Relay worker: {}", e);
            }
        }
    });

    // 7. Tonic gRPC Server
    let grpc_service = GrpcIdentityService::new(
        user_repo.clone(),
        rbac_repo.clone(),
        session_store.clone(),
        sessions_use_case.clone(),
        crypto.clone(),
    );

    let grpc_addr: SocketAddr = format!("0.0.0.0:{}", config.grpc_port).parse()?;
    info!("Starting gRPC server on {}", grpc_addr);

    tokio::spawn(async move {
        if let Err(e) = tonic::transport::Server::builder()
            .add_service(IdentityServiceServer::new(grpc_service))
            .serve(grpc_addr)
            .await
        {
            error!("gRPC server failed: {}", e);
        }
    });

    // 8. Axum HTTP Server
    let app_state = AppState {
        register_use_case,
        login_use_case,
        mfa_use_case,
        sessions_use_case,
        oauth_use_case,
        crypto,
        issuer: config.oauth_issuer.clone(),
    };

    let router = create_router(app_state);
    let http_addr: SocketAddr = format!("0.0.0.0:{}", config.http_port).parse()?;
    info!("Starting HTTP REST API server on {}", http_addr);

    let listener = TcpListener::bind(http_addr).await?;
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("identity-service shut down gracefully");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received, draining active requests...");
}
