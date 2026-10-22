use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub http_port: u16,
    pub grpc_port: u16,
    pub database_url: String,
    pub redis_url: String,
    pub kafka_brokers: Vec<String>,
    pub kafka_identity_topic: String,
    pub jwt_secret: String,
    pub access_token_ttl_seconds: i64,
    pub refresh_token_ttl_seconds: i64,
    pub password_reset_token_ttl_seconds: i64,
}

impl Config {
    pub fn from_env() -> Result<Self, anyhow::Error> {
        let _ = dotenvy::dotenv();

        let http_port = env::var("HTTP_PORT")
            .unwrap_or_else(|_| "8001".to_string())
            .parse::<u16>()?;

        let grpc_port = env::var("GRPC_PORT")
            .unwrap_or_else(|_| "50051".to_string())
            .parse::<u16>()?;

        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres_secret_pass@localhost:5432/identity_db".to_string());

        let redis_url = env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://:redis_secret_pass@localhost:6379/0".to_string());

        let kafka_brokers_str = env::var("KAFKA_BROKERS")
            .unwrap_or_else(|_| "localhost:9092".to_string());
        let kafka_brokers = kafka_brokers_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let kafka_identity_topic = env::var("KAFKA_IDENTITY_TOPIC")
            .unwrap_or_else(|_| "identity.events".to_string());

        let jwt_secret = env::var("JWT_SECRET")
            .unwrap_or_else(|_| "super_secret_jwt_hmac_key_min_32_bytes_long_here_12345".to_string());

        let access_token_ttl_seconds = env::var("ACCESS_TOKEN_TTL_SECONDS")
            .unwrap_or_else(|_| "900".to_string())
            .parse::<i64>()?;

        let refresh_token_ttl_seconds = env::var("REFRESH_TOKEN_TTL_SECONDS")
            .unwrap_or_else(|_| "604800".to_string())
            .parse::<i64>()?;

        let password_reset_token_ttl_seconds = env::var("PASSWORD_RESET_TOKEN_TTL_SECONDS")
            .unwrap_or_else(|_| "900".to_string())
            .parse::<i64>()?;

        Ok(Config {
            http_port,
            grpc_port,
            database_url,
            redis_url,
            kafka_brokers,
            kafka_identity_topic,
            jwt_secret,
            access_token_ttl_seconds,
            refresh_token_ttl_seconds,
            password_reset_token_ttl_seconds,
        })
    }
}
