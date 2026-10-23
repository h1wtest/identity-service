use platform_contracts::Envelope;
use std::future::Future;
use uuid::Uuid;

/// Application publication port: implementations must acknowledge broker acceptance,
/// preserve event identity, and never report a failed/ambiguous send as success.
pub trait Publisher: Send + Sync {
    fn publish(
        &self,
        topic: &str,
        event: &Envelope,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// Explicit FNV-1a over canonical aggregate UUID text; stable across processes.
pub fn partition_for(aggregate_id: Uuid) -> i32 {
    let mut hash = 2_166_136_261_u32;
    for byte in aggregate_id.to_string().bytes() {
        hash = (hash ^ u32::from(byte)).wrapping_mul(16_777_619);
    }
    (hash % platform_contracts::PARTITIONS as u32) as i32
}
