use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use opentelemetry::trace::TraceContextExt;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing_opentelemetry::OpenTelemetrySpanExt;
pub mod adapters;
pub mod application;
pub mod auth;
pub mod config;
pub mod domain;
pub mod events;
pub mod oauth;
pub mod outbox;
pub mod rekey;
pub mod security;
pub mod telemetry;
use config::Config;
use security::Crypto;

pub type ApiResult<T> = Result<T, ApiError>;
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
}
impl ApiError {
    pub fn bad(code: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
        }
    }
    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthenticated",
        }
    }
    pub fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
        }
    }
    pub fn dependency() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "dependency_unavailable",
        }
    }
    pub fn limited() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "rate_limited",
        }
    }
}
impl From<sqlx::Error> for ApiError {
    fn from(_: sqlx::Error) -> Self {
        Self::dependency()
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({"error":self.code,"code":self.code})),
        )
            .into_response()
    }
}
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
    pub crypto: Arc<Crypto>,
    pub passwords: Arc<Semaphore>,
    pub metrics: Arc<Metrics>,
}
pub struct Metrics {
    registry: Registry,
    requests: IntCounterVec,
    duration: HistogramVec,
}
impl Metrics {
    fn new() -> anyhow::Result<Self> {
        let registry = Registry::new();
        let requests = IntCounterVec::new(
            Opts::new("http_requests_total", "Completed HTTP requests"),
            &["method", "status"],
        )?;
        let duration = HistogramVec::new(
            HistogramOpts::new("http_request_duration_seconds", "HTTP latency"),
            &["method"],
        )?;
        registry.register(Box::new(requests.clone()))?;
        registry.register(Box::new(duration.clone()))?;
        Ok(Self {
            registry,
            requests,
            duration,
        })
    }
}
impl AppState {
    pub async fn connect(config: Config) -> anyhow::Result<Self> {
        let crypto = Arc::new(Crypto::new(&config)?);
        let db = PgPoolOptions::new()
            .max_connections(20)
            .acquire_timeout(std::time::Duration::from_secs(3))
            .connect(&config.database_url)
            .await?;
        Ok(Self {
            db,
            config: Arc::new(config),
            crypto,
            passwords: Arc::new(Semaphore::new(4)),
            metrics: Arc::new(Metrics::new()?),
        })
    }
}
pub async fn migrate(db: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(db).await?;
    encrypt_legacy_mfa(db).await?;
    Ok(())
}

/// Migration-only data cutover: runtime never accepts unencrypted factor secrets.
pub async fn encrypt_legacy_mfa(db: &PgPool) -> anyhow::Result<()> {
    use base64::Engine;
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(742915831)")
        .execute(&mut *tx)
        .await?;
    let rows: Vec<(uuid::Uuid, String)> = sqlx::query_as(
        "SELECT user_id,secret_key FROM mfa_secrets WHERE secret_key NOT LIKE 'enc:%' FOR UPDATE",
    )
    .fetch_all(&mut *tx)
    .await?;
    if !rows.is_empty() {
        let key = std::env::var("MFA_ENCRYPTION_KEY").map_err(|_| {
            anyhow::anyhow!("MFA_ENCRYPTION_KEY required to migrate existing MFA secrets")
        })?;
        let key: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(key)
            .map_err(|_| anyhow::anyhow!("MFA_ENCRYPTION_KEY must be base64 of 32 bytes"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("MFA_ENCRYPTION_KEY must be base64 of 32 bytes"))?;
        let cipher = security::PayloadCipher::new(key);
        for (user_id, secret) in rows {
            let encrypted = cipher.encrypt(&user_id.to_string(), secret.as_bytes())?;
            sqlx::query("UPDATE mfa_secrets SET secret_key=$2,updated_at=now() WHERE user_id=$1")
                .bind(user_id)
                .bind(format!("enc:{encrypted}"))
                .execute(&mut *tx)
                .await?;
        }
    }
    sqlx::query("ALTER TABLE mfa_secrets VALIDATE CONSTRAINT mfa_secret_encrypted")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health/live", get(|| async { StatusCode::OK }))
        .route("/health/ready", get(ready))
        .route("/api/v1/auth/ready", get(ready))
        .route("/metrics", get(metrics))
        .with_state(state.clone())
        .merge(auth::router(state.clone()))
        .merge(oauth::router(state.clone()))
        .layer(axum::extract::DefaultBodyLimit::max(16384))
        .layer(middleware::from_fn_with_state(state, observe))
}
async fn schema_ready(state: &AppState) -> bool {
    let result=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=7 AND success) AND to_regclass('identity_challenges') IS NOT NULL AND to_regclass('oauth_refresh_tokens') IS NOT NULL AND EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='outbox_events' AND column_name='lease_token') AND EXISTS(SELECT 1 FROM pg_constraint WHERE conname='mfa_secret_encrypted' AND conrelid='mfa_secrets'::regclass AND convalidated) AND NOT EXISTS(SELECT 1 FROM mfa_secrets WHERE secret_key NOT LIKE 'enc:%')").fetch_one(&state.db).await;
    result.unwrap_or(false)
}
async fn ready(State(state): State<AppState>) -> Response {
    if schema_ready(&state).await {
        Json(serde_json::json!({"ready":true})).into_response()
    } else {
        ApiError::dependency().into_response()
    }
}
async fn metrics(State(state): State<AppState>) -> Response {
    let mut bytes = Vec::new();
    let encoder = TextEncoder::new();
    if encoder
        .encode(&state.metrics.registry.gather(), &mut bytes)
        .is_err()
    {
        return ApiError::dependency().into_response();
    }
    let (pending,age)=sqlx::query_as::<_,(i64,f64)>("SELECT count(*),COALESCE(EXTRACT(EPOCH FROM now()-min(created_at)),0)::float8 FROM outbox_events WHERE NOT is_processed").fetch_one(&state.db).await.unwrap_or((0,0.0));
    let ready = if schema_ready(&state).await { 1 } else { 0 };
    bytes.extend_from_slice(format!("# TYPE outbox_pending gauge\noutbox_pending {pending}\n# TYPE outbox_oldest_age_seconds gauge\noutbox_oldest_age_seconds {age}\n# TYPE service_ready gauge\nservice_ready {ready}\n# TYPE db_pool_connections gauge\ndb_pool_connections {}\n",state.db.size()).as_bytes());
    ([("content-type", "text/plain; version=0.0.4")], bytes).into_response()
}
struct HeaderCarrier<'a>(&'a axum::http::HeaderMap);
impl opentelemetry::propagation::Extractor for HeaderCarrier<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|v| v.as_str()).collect()
    }
}
async fn observe(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    let trusted_gateway = request
        .headers()
        .get("x-gateway-token")
        .and_then(|value| value.to_str().ok())
        .map(|value| security::constant_eq(value, &state.config.gateway_internal_token))
        .unwrap_or(false);
    request.headers_mut().remove("x-gateway-token");
    if !trusted_gateway {
        let peer = request
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|info| info.0.ip().to_string());
        request.headers_mut().remove("x-real-ip");
        if let Some(value) = peer.and_then(|value| HeaderValue::from_str(&value).ok()) {
            request.headers_mut().insert("x-real-ip", value);
        }
    }
    let start = std::time::Instant::now();
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let parent = opentelemetry::global::get_text_map_propagator(|p| {
        p.extract(&HeaderCarrier(request.headers()))
    });
    let span =
        tracing::info_span!("http.request",http.method=%method,http.route=%path,otel.kind="server");
    // No OpenTelemetry layer is installed when OTLP export is disabled.
    let _ = span.set_parent(parent);
    let ctx = span.context();
    let sc = ctx.span().span_context().clone();
    let traceparent = if sc.is_valid() {
        Some(format!("00-{}-{}-01", sc.trace_id(), sc.span_id()))
    } else {
        None
    };
    if let Some(value) = traceparent
        .as_ref()
        .and_then(|v| HeaderValue::from_str(v).ok())
    {
        request.headers_mut().insert("traceparent", value);
    }
    use tracing::Instrument;
    let mut response = next.run(request).instrument(span).await;
    state
        .metrics
        .requests
        .with_label_values(&[&method, response.status().as_str()])
        .inc();
    state
        .metrics
        .duration
        .with_label_values(&[&method])
        .observe(start.elapsed().as_secs_f64());
    if let Some(value) = traceparent.and_then(|v| HeaderValue::from_str(&v).ok()) {
        response.headers_mut().insert("traceparent", value);
    }
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    if matches!(
        response.status(),
        StatusCode::BAD_REQUEST
            | StatusCode::UNPROCESSABLE_ENTITY
            | StatusCode::UNSUPPORTED_MEDIA_TYPE
            | StatusCode::PAYLOAD_TOO_LARGE
    ) && !response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("application/json"))
        .unwrap_or(false)
    {
        return ApiError::bad("invalid_request").into_response();
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_preserve_prometheus_text_counters_and_histograms() {
        let metrics = Metrics::new().unwrap();
        metrics.requests.with_label_values(&["GET", "200"]).inc();
        metrics.duration.with_label_values(&["GET"]).observe(0.25);
        let mut bytes = Vec::new();
        TextEncoder::new()
            .encode(&metrics.registry.gather(), &mut bytes)
            .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        for sample in [
            "# TYPE http_requests_total counter\n",
            "http_requests_total{method=\"GET\",status=\"200\"} 1\n",
            "# TYPE http_request_duration_seconds histogram\n",
            "http_request_duration_seconds_bucket{method=\"GET\",le=\"0.25\"} 1\n",
            "http_request_duration_seconds_sum{method=\"GET\"} 0.25\n",
            "http_request_duration_seconds_count{method=\"GET\"} 1\n",
        ] {
            assert!(text.contains(sample), "missing Prometheus sample: {sample}");
        }
    }
}
