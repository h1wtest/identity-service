use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;
use rskafka::client::partition::PartitionClient;
use rskafka::client::ClientBuilder;
use rskafka::record::Record;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::domain::ports::OutboxRepository;

pub struct OutboxRelayWorker {
    outbox_repo: Arc<dyn OutboxRepository>,
    partition_client: PartitionClient,
}

impl OutboxRelayWorker {
    pub async fn new(
        outbox_repo: Arc<dyn OutboxRepository>,
        brokers: Vec<String>,
        topic: &str,
    ) -> Result<Self, anyhow::Error> {
        info!("Connecting Outbox Relay to Kafka brokers: {:?}", brokers);
        let client = ClientBuilder::new(brokers).build().await?;
        let partition_client = client
            .partition_client(topic, 0, rskafka::client::partition::UnknownTopicHandling::Error)
            .await?;

        Ok(Self {
            outbox_repo,
            partition_client,
        })
    }

    pub async fn run(self) {
        info!("Outbox Relay worker started running");
        loop {
            if let Err(e) = self.process_batch().await {
                error!("Error processing outbox events batch: {}", e);
            }
            sleep(Duration::from_millis(500)).await;
        }
    }

    async fn process_batch(&self) -> Result<(), anyhow::Error> {
        let events = self.outbox_repo.fetch_unprocessed(50).await?;
        if events.is_empty() {
            return Ok(());
        }

        info!("Outbox Relay found {} events to publish", events.len());

        for event in events {
            let key = event.aggregate_id.as_bytes().to_vec();
            let value = serde_json::to_vec(&event.payload)?;

            let record = Record {
                key: Some(key),
                value: Some(value),
                headers: Default::default(),
                timestamp: Utc::now(),
            };

            match self.partition_client.produce(vec![record], rskafka::client::partition::Compression::NoCompression).await {
                Ok(_) => {
                    info!(
                        "Successfully published outbox event {} ({}) to Kafka",
                        event.id, event.event_type
                    );
                    if let Err(e) = self.outbox_repo.mark_processed(event.id).await {
                        error!("Failed to mark outbox event {} as processed: {}", event.id, e);
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to publish outbox event {} to Kafka: {}",
                        event.id, e
                    );
                    let _ = self.outbox_repo.record_failure(event.id, &e.to_string()).await;
                }
            }
        }

        Ok(())
    }
}
