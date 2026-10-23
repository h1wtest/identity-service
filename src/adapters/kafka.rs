use crate::{
    config::Config,
    domain::events::{partition_for, Publisher},
};
use platform_contracts::{Envelope, COMMAND_TOPIC, IDENTITY_TOPIC, PARTITIONS};
use rskafka::{
    client::{
        partition::{Compression, UnknownTopicHandling},
        Client, ClientBuilder, Credentials, SaslConfig,
    },
    record::Record,
};
use std::{collections::BTreeMap, sync::Arc};

/// Construct the actual authenticated transport. No plaintext or anonymous fallback.
pub async fn client(config: &Config) -> anyhow::Result<Client> {
    if config.kafka_tls_ca_file.is_empty()
        || config.kafka_sasl_username.is_empty()
        || config.kafka_sasl_password.is_empty()
    {
        anyhow::bail!("Kafka TLS CA and SASL credentials required");
    }
    let pem = tokio::fs::read(&config.kafka_tls_ca_file).await?;
    let mut input = std::io::Cursor::new(pem);
    let mut roots = rustls::RootCertStore::empty();
    let mut certificates = 0;
    for certificate in rustls_pemfile::certs(&mut input) {
        roots.add(certificate?)?;
        certificates += 1;
    }
    if certificates == 0 {
        anyhow::bail!("Kafka TLS CA contains no certificates");
    }
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    ClientBuilder::new(config.kafka_brokers.clone())
        .tls_config(Arc::new(tls))
        .sasl_config(SaslConfig::ScramSha256(Credentials::new(
            config.kafka_sasl_username.clone(),
            config.kafka_sasl_password.clone(),
        )))
        .build()
        .await
        .map_err(Into::into)
}

pub struct KafkaPublisher {
    client: Client,
}
impl KafkaPublisher {
    pub async fn connect(config: &Config) -> anyhow::Result<Self> {
        let client = client(config).await?;
        let topics = client.list_topics().await?;
        for name in [IDENTITY_TOPIC, COMMAND_TOPIC] {
            let topic = topics
                .iter()
                .find(|topic| topic.name == name)
                .ok_or_else(|| anyhow::anyhow!("required event topic missing"))?;
            if topic.partitions.len() != PARTITIONS as usize
                || !(0..PARTITIONS).all(|p| topic.partitions.contains(&p))
            {
                anyhow::bail!("event topic must have exactly six partitions");
            }
        }
        Ok(Self { client })
    }
}

impl Publisher for KafkaPublisher {
    async fn publish(&self, topic: &str, event: &Envelope) -> anyhow::Result<()> {
        event.validate().map_err(anyhow::Error::msg)?;
        if platform_contracts::topic(&event.event_type).map_err(anyhow::Error::msg)? != topic {
            anyhow::bail!("stored envelope topic mismatch");
        }
        let mut headers = BTreeMap::new();
        if let Some(trace) = &event.traceparent {
            headers.insert("traceparent".into(), trace.as_bytes().to_vec());
        }
        headers.insert("event_id".into(), event.event_id.to_string().into_bytes());
        let record = Record {
            key: Some(event.aggregate_id.to_string().into_bytes()),
            value: Some(serde_json::to_vec(event)?),
            headers,
            timestamp: event.occurred_at,
        };
        let partition = self
            .client
            .partition_client(
                topic,
                partition_for(event.aggregate_id),
                UnknownTopicHandling::Error,
            )
            .await?;
        partition
            .produce(vec![record], Compression::NoCompression)
            .await?;
        Ok(())
    }
}
