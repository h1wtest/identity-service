use opentelemetry::trace::TracerProvider;
use opentelemetry_sdk::{
    propagation::TraceContextPropagator,
    trace::{span_processor_with_async_runtime::BatchSpanProcessor, SdkTracerProvider},
    Resource,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn init_telemetry() -> anyhow::Result<Option<SdkTracerProvider>> {
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
        let provider = build_provider(
            &endpoint,
            std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "identity-service".into()),
        )?;
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

fn build_provider(endpoint: &str, service_name: String) -> anyhow::Result<SdkTracerProvider> {
    use opentelemetry_otlp::WithExportConfig;
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(format!("{}/v1/traces", endpoint.trim_end_matches('/')))
        .with_timeout(std::time::Duration::from_secs(3))
        .build()?;
    let processor =
        BatchSpanProcessor::builder(exporter, opentelemetry_sdk::runtime::Tokio).build();
    Ok(SdkTracerProvider::builder()
        .with_span_processor(processor)
        .with_resource(
            Resource::builder_empty()
                .with_attributes([opentelemetry::KeyValue::new("service.name", service_name)])
                .build(),
        )
        .build())
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
    // Without an OTLP layer, propagation is intentionally inactive.
    let _ = span.set_parent(context);
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::TraceContextExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn otlp_http_exports_completed_span_with_original_w3c_parent() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let receiver = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let (header_length, body_length) = loop {
                let mut bytes = [0; 4096];
                let count = stream.read(&mut bytes).await.unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&bytes[..count]);
                if let Some(end) = request.windows(4).position(|v| v == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&request[..end]).unwrap();
                    assert!(headers.starts_with("POST /v1/traces HTTP/1.1\r\n"));
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    break (end + 4, length);
                }
            };
            while request.len() < header_length + body_length {
                let mut bytes = [0; 4096];
                let count = stream.read(&mut bytes).await.unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&bytes[..count]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            request[header_length..].to_vec()
        });
        let provider = build_provider(&endpoint, "identity-export-regression".into()).unwrap();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("regression")));
        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
        {
            let _guard = tracing::subscriber::set_default(subscriber);
            let span = tracing::info_span!("exported-regression-span");
            attach_traceparent(
                &span,
                "00-11111111111111111111111111111111-2222222222222222-01",
            );
            use tracing_opentelemetry::OpenTelemetrySpanExt;
            assert_eq!(
                span.context().span().span_context().trace_id().to_string(),
                "11111111111111111111111111111111"
            );
        }
        let flush_provider = provider.clone();
        tokio::task::spawn_blocking(move || flush_provider.force_flush())
            .await
            .unwrap()
            .unwrap();
        let body = tokio::time::timeout(std::time::Duration::from_secs(5), receiver)
            .await
            .unwrap()
            .unwrap();
        for expected in [
            b"identity-export-regression".as_slice(),
            b"exported-regression-span",
            &[0x11; 16],
        ] {
            assert!(body.windows(expected.len()).any(|value| value == expected));
        }
        tokio::task::spawn_blocking(move || provider.shutdown())
            .await
            .unwrap()
            .unwrap();
    }
}
