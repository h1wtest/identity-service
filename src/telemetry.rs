use opentelemetry::trace::TracerProvider;
use opentelemetry_sdk::{
    propagation::TraceContextPropagator, trace::TracerProvider as SdkTracerProvider, Resource,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn init_telemetry() -> anyhow::Result<Option<SdkTracerProvider>> {
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
        use opentelemetry_otlp::WithExportConfig;
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(format!("{}/v1/traces", endpoint.trim_end_matches('/')))
            .with_timeout(std::time::Duration::from_secs(3))
            .build()?;
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
            .with_resource(Resource::new(vec![opentelemetry::KeyValue::new(
                "service.name",
                std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "identity-service".into()),
            )]))
            .build();
        let tracer = provider.tracer("identity-service");
        opentelemetry::global::set_tracer_provider(provider.clone());
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .try_init()?;
        Ok(Some(provider))
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .try_init()?;
        Ok(None)
    }
}

pub fn attach_traceparent(span: &tracing::Span, parent: &str) {
    struct Carrier<'a>(&'a str);
    impl opentelemetry::propagation::Extractor for Carrier<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            if key == "traceparent" {
                Some(self.0)
            } else {
                None
            }
        }
        fn keys(&self) -> Vec<&str> {
            vec!["traceparent"]
        }
    }
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    let context = opentelemetry::global::get_text_map_propagator(|p| p.extract(&Carrier(parent)));
    span.set_parent(context);
}
