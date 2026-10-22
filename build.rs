use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (proto_base, identity_proto, events_proto) = if Path::new("proto/identity/v1/identity.proto").exists() {
        (
            "proto",
            "proto/identity/v1/identity.proto",
            "proto/events/v1/auth_events.proto",
        )
    } else {
        (
            "../platform-contracts/proto",
            "../platform-contracts/proto/identity/v1/identity.proto",
            "../platform-contracts/proto/events/v1/auth_events.proto",
        )
    };

    println!("cargo:rerun-if-changed={}", identity_proto);
    println!("cargo:rerun-if-changed={}", events_proto);

    tonic_build::configure()
        .compile_protos(&[identity_proto, events_proto], &[proto_base])?;

    Ok(())
}
