fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../platform-contracts/proto/identity/v1/identity.proto");
    println!("cargo:rerun-if-changed=../platform-contracts/proto/events/v1/auth_events.proto");

    tonic_build::configure()
        .compile_protos(
            &[
                "../platform-contracts/proto/identity/v1/identity.proto",
                "../platform-contracts/proto/events/v1/auth_events.proto",
            ],
            &["../platform-contracts/proto"],
        )?;

    Ok(())
}
