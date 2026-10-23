FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS builder
RUN printf 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20261022T000000Z bookworm main\ndeb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20261022T000000Z bookworm-security main\n' > /etc/apt/sources.list && rm -f /etc/apt/sources.list.d/debian.sources
RUN apt-get -o APT::Update::Error-Mode=any update && apt-get install -y --no-install-recommends musl-tools cmake && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /build
COPY platform-contracts/rust ./platform-contracts/rust
COPY identity-service ./identity-service
WORKDIR /build/identity-service
ENV CC_x86_64_unknown_linux_musl=musl-gcc
RUN cargo build --release --locked --target x86_64-unknown-linux-musl

FROM scratch AS runtime
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /build/identity-service/target/x86_64-unknown-linux-musl/release/identity-service /app/identity-service
COPY --from=builder /build/identity-service/Cargo.lock /usr/share/identity-service/Cargo.lock
COPY --from=builder /build/identity-service/Cargo.toml /usr/share/identity-service/Cargo.toml
WORKDIR /app
USER 10001:10001
EXPOSE 8001
ENTRYPOINT ["/app/identity-service"]
