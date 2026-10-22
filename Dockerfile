# ==========================================
# Build Stage
# ==========================================
FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev protobuf-dev cmake make g++

WORKDIR /build

# Copy platform-contracts proto definitions
COPY platform-contracts/proto ./platform-contracts/proto

# Copy identity-service source
COPY identity-service ./identity-service

WORKDIR /build/identity-service

RUN cargo build --release

# ==========================================
# Runtime Stage (Minimal & Secure Non-Root)
# ==========================================
FROM alpine:3.21 AS runner

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup

WORKDIR /app

COPY --from=builder /build/identity-service/target/release/identity-service /app/identity-service
COPY --from=builder /build/identity-service/migrations /app/migrations

USER 10001:10001

EXPOSE 8001 50051

ENTRYPOINT ["/app/identity-service"]
