# Identity service

Rust/Axum identity owner. PostgreSQL is authoritative for users, sessions, MFA challenges, recovery, OAuth grants and the transactional outbox. No Redis credential authority, shared HMAC JWT secret, unauthenticated gRPC endpoint or client-supplied user identity remains.

## Commands and deployment

Use the isolated platform-infra bootstrap, which generates credentials and TLS/RSA keys outside Git. Build from the workspace root:

```sh
docker build -f identity-service/Dockerfile -t identity-service:<source-sha> .
```

The final image is `scratch`: a musl-static Rust executable and the pinned-builder CA bundle, running uid 10001 without shell or shared system libraries. Build targets `x86_64-unknown-linux-musl`; this local platform image is AMD64, not a claim of verified ARM64 support. RSA key validation/public derivation uses ring; JWT signatures use jsonwebtoken's AWS-LC backend, with audited PEM/PKCS1/SPKI DER parsers and no custom RSA arithmetic. OpenSSL is not a runtime/dependency requirement. Builder apt uses a fixed Debian snapshot and strict error mode; its CMake/musl toolchain builds AWS-LC statically. Parent verifies the actual binary with `file`/`ldd` and scans application dependencies and final image; no CVE suppression or passing scan is implied by the scratch base alone.


The checked-in `rust-toolchain.toml` pins Rust 1.99.0. Cargo.lock is the dependency authority; builds use `--locked`. Empty secrets fail closed. `MFA_ENCRYPTION_KEY` (identity only) and distinct `DELIVERY_ENCRYPTION_KEY` (identity and notification worker only) are independent base64 32-byte keys. Caller credentials and `GATEWAY_INTERNAL_TOKEN` are distinct random strings of at least 32 characters. TLS is mandatory on port 8001. Gateway authentication protects forwarded client IP; untrusted requests use socket peer IP. Kafka requires CA/hostname verification and SCRAM-SHA256 using `KAFKA_TLS_CA_FILE`, `KAFKA_SASL_USERNAME`, `KAFKA_SASL_PASSWORD`, without plaintext fallback. Mount keys as uid 10001. Keep previous public signing key and distinct kid while old tokens expire, never distribute its private key.

Dependency remediation uses SQLx **0.9.0** with `default-features = false` and explicit PostgreSQL, Tokio/rustls-ring, UUID/chrono/JSON, macros and migration support. The active driver is PostgreSQL only; no MySQL authentication or `rsa` crate is used. Cargo's [weak-feature lockfile issue](https://github.com/transact-rs/sqlx/issues/3211) still records optional `sqlx-mysql`/`sqlx-sqlite` 0.9.0 metadata, so lockfile presence alone is not proof a driver is compiled. Unlike 0.8.6, the maintained 0.9.0 MySQL dependency does not enable RSA by default. SQLx migrations remain embedded with `sqlx::migrate!`; prepared statements, checksums and transactional authorization are unchanged. Test-only dynamic schema identifiers are locally generated UUIDs and explicitly marked `AssertSqlSafe` for SQLx 0.9.

Prometheus **0.14.0** disables unused default protobuf encoding: `/metrics` continues to serve Prometheus **text/plain; version=0.0.4**, including counters, latency histogram buckets/sum/count and operational gauges. This removes protobuf 2.28.0 rather than waiving RUSTSEC-2024-0437; binary protobuf metrics were never exposed. HTTPS uses axum-server **0.8.0**, whose PEM loader uses maintained `rustls-pki-types`; the direct Kafka CA loader uses `CertificateDer::pem_slice_iter` from resolved `rustls-pki-types` **1.15.1**. `rustls-pemfile` is no longer a dependency. HTTPS certificate chains and PKCS1/PKCS8 RSA keys remain supported; signing/JWKS still supports PKCS1/PKCS8 private keys and PKCS1/SPKI previous public keys through the existing ring/DER path. Empty, malformed or invalid Kafka CA material fails before a broker connection; hostname/CA verification and SCRAM remain mandatory.

The final-image findings additionally require jsonwebtoken **10.4.0** (patched floor **10.3.0** for [CVE-2026-25537](https://github.com/Keats/jsonwebtoken/security/advisories/GHSA-h395-gr6q-cpjc)) and opentelemetry_sdk **0.32.1** ([CVE-2026-48504](https://github.com/open-telemetry/opentelemetry-rust/security/advisories/GHSA-w9wp-h8wv-79jx)). JWT enables only `aws_lc_rs` and PEM import, not the `rust_crypto` backend that would restore vulnerable `rsa`; RS256, kid/issuer checks and key formats remain unchanged. The claim advisory concerns malformed optional standard claims; this service already requires typed expiry, and its signed malformed-expiry regression remains fail-closed. Telemetry uses matching OpenTelemetry/OTLP **0.32.0** and tracing-opentelemetry **0.33.0**, retaining W3C TraceContext, service resources, three-second OTLP HTTP/protobuf timeout and Tokio asynchronous batch export. The optional exporter uses an explicit async processor with the async reqwest client rather than the SDK's new blocking-client defaults. The baggage advisory affects oversized `BaggagePropagator` headers; this service installs only TraceContext propagation, but still upgrades the SDK rather than suppressing the finding. A real local HTTP collector regression covers completed-span export and original trace ID propagation. Full tests, Cargo audit and the final immutable-image scan must be rerun for this graph.

```sh
# Fresh schema needs DATABASE_URL only; legacy MFA additionally requires the new identity-only key.
DATABASE_URL="$IDENTITY_MIGRATION_URL" MFA_ENCRYPTION_KEY="$MFA_KEY" identity-service migrate
# All regular runtime settings must also be supplied for bootstrap.
ADMIN_EMAIL="$EMAIL" ADMIN_PASSWORD="$PASSWORD" identity-service bootstrap-admin
identity-service serve
```

Migration 0007 rejects new plaintext MFA; a separate advisory-locked transaction seals legacy rows and validates its constraint. Missing/malformed MFA key changes no rows and leaves readiness false; a correct-key retry is atomic and idempotent. Runtime never reads plaintext secrets or runs migration DDL.

Previously encrypted common-key state requires the explicit migration-only command before switching runtime keys:
```sh
DATABASE_URL="$IDENTITY_MIGRATION_URL" LEGACY_ENCRYPTION_KEY="$OLD_KEY" \
MFA_ENCRYPTION_KEY="$MFA_KEY" DELIVERY_ENCRYPTION_KEY="$DELIVERY_KEY" identity-service rekey
```
Stop legacy writers and drain durable delivery/broker work through the platform operator workflow first. Rekey needs no signing/TLS/broker runtime configuration. It locks and rewraps active/pending MFA and retained encrypted outbox envelopes in one transaction, preserving IDs and payload metadata. Already-new ciphertext is verified and unchanged, so retries are idempotent. Unknown ciphertext/schema or plaintext sensitive commands fail closed and roll back every row. Retain the legacy key in restricted backup until identity and notification migrations and delivery verification all succeed. Never delete retained broker commands merely to pass a key migration gate.


Migration uses SQLx version/checksum records and advisory serialization, never resets user data. Migration 0004 revokes legacy Redis-backed sessions because their cookies cannot be safely promoted. Migration 0005 requires pending legacy outbox entries to be drained with the former producer before cutover; processed history is retained. Runtime needs CONNECT, schema USAGE, DML on owned tables and USAGE/SELECT on sequences; migration credentials must not be used by the server. The historical uuid-ossp extension must be pre-provisioned or migration role must be allowed to create it.

Bootstrap is serialized and idempotent for an already-admin account; it never replaces its password and refuses to elevate a pre-existing ordinary account. The bootstrap account is email verified, but admin operations require MFA enrollment, then an MFA-authenticated session. Enrollment always needs recent password reauthentication; replacing an active factor also needs its current TOTP or a one-use recovery code. Confirming enrollment clears the reauthentication grant. Admin MFA must be refreshed within 15 minutes through `/reauth`; ordinary sessions last 24 hours.

## Browser and internal API

Browser session `sso_session` is opaque, HttpOnly, Secure, SameSite=Lax and stored as a SHA-256 hash in SQL. `GET /api/v1/auth/csrf` sets a readable Secure `sso_csrf`. Every browser mutation requires exact `Origin: PUBLIC_ORIGIN`, matching `X-CSRF-Token` and cookie; authenticated mutations additionally match the authoritative session hash. A SPA reload calls `/api/v1/auth/me`. Logout, revoke, password change/reset and ban immediately invalidate SQL sessions, including previously signed OAuth tokens. A session cannot be revoked by another user.

Auth endpoints implement registration/email verification, login/MFA challenge, `/sessions`, `/reauth`, pending MFA setup/enable/disable, password forgot/reset/change. Passwords are 12–1024 bytes, Argon2id runs off the async executor behind four permits. Persistent SQL rate windows cover authentication/recovery operations. Email is normalized, errors are redacted `{error,code}`, dependency failure is 503 and never authenticates. Recovery replies do not disclose whether an account exists; delivery credentials are encrypted before SQL outbox insertion. TOTP steps and recovery codes are consumed once under row locks. A failed or abandoned setup never changes an active secret.

Internal callers use HTTPS and `X-Service-Token`; unknown tokens are denied. `/internal/v1/introspect` accepts live session/access credentials plus browser Origin/CSRF context and applies permissions/MFA. Only the admin caller token can list users or issue ban/unban; identity independently validates the user's live actor session and permission. Profile/notification tokens cannot issue admin commands. No bootstrap HTTP endpoint exists.

## OAuth/OIDC

Discovery `/.well-known/openid-configuration`, public JWKS, `/oauth/authorize`, form-encoded `/oauth/token`, `/oauth/userinfo`. Authorization Code with mandatory S256 PKCE, exact HTTPS redirect registration, state and nonce, RS256/kid/iss/aud/iat/exp/sid/token-use, registered scopes only, public clients and confidential client authentication. Public development client `web-demo` has callback `https://localhost:8448/oidc/callback` and scopes openid/email/profile/offline_access; this explicitly trusted first-party client uses pre-registered consent. Do not register arbitrary third-party clients without implementing a user consent policy. Historical client data is preserved but insecure HTTP callbacks are rejected. Code/refresh redemption locks prevent parallel branches; consumed token reuse revokes the grant family and its source session. Tokens cannot outlive SQL session validity. No OIDC certification is claimed.
Client-audience OIDC tokens authorize only `/oauth/userinfo`, never management/admin/Go resource APIs even with an ambient cookie. Those APIs accept browser sessions or resource tokens with `aud=PUBLIC_ORIGIN` and `platform:api`; no public resource-token grant is issued without an explicit client authorization policy.


## Outbox and observability

State mutation and canonical event insertion share one SQL transaction. Public `identity.events.v1` contains no reset/verification secrets. Sensitive `notification.commands.v1` uses delivery-only AES-256-GCM, base64(nonce12|ciphertext|tag16), event UUID text as AAD. MFA uses its distinct identity-only key with user UUID AAD. Restrict command retention/access to 24h; rotate keys through deliberate data migrations, not changes that lose decryption.

Relay claims durable leases, never overtakes an older unprocessed event for the same aggregate, chooses one of exactly six partitions from aggregate UUID key and waits for broker acknowledgement before marking processed. Failure preserves a retriable row with bounded jitter; lease expiry recovers crashed workers. Delivery is at-least-once, not exactly-once. Kafka outage does not block login while PostgreSQL can commit the outbox. Monitor backlog age and provision capacity; no in-memory successful fallback exists.

`/health/live` is process liveness. `/health/ready` (also `/api/v1/auth/ready` for local acceptance) checks schema/dependencies; missing schema is never Ready. `/metrics` is internal-only via network/gateway policy and exposes HTTP counts/latency, SQL pool, readiness and outbox age/count. Structured logs do not contain credential bodies. HTTP W3C context is propagated into events and linked relay spans, with OTLP HTTP export when configured.

## Verification and local acceptance

The integration controller executed the following local checks after implementation: strict `cargo clippy --locked --all-targets -- -D warnings`; non-database tests; 36 selected PostgreSQL security/lease/readiness regressions, the rekey regression, the real TLS/SCRAM Kafka relay regression, and six RSA import/JWKS/signing/rotation regressions. These passed. The static-musl image was inspected with `file`/`readelf` (static PIE, no `INTERP`) and scanned with Trivy: the scanner detected its embedded Cargo.lock and reported zero HIGH/CRITICAL findings, rather than treating an empty scratch-image scan as evidence.

Strict HTTPS acceptance also passed against actual services: registration and Mailpit verification, keyed Kafka/profile projection, two-user ownership and CSRF denial, immediate revoke across identity/profile, OpenSSL-verified RS256/JWKS/nonce/state/PKCE OIDC and refresh reuse, MFA challenge/recovery replay protection, setup preserving the active factor, actual recovery email/reset token single-use, password change/revocation and logout. Real browser OIDC acceptance was exercised by the controller. This does not constitute OIDC certification, production acceptance, real Telegram delivery, or every broader platform fault/UI/observability gate.

To reproduce, supply full `.env.example` configuration with disposable credentials, generated RSA/TLS keys, distinct MFA/delivery keys and a verified TLS/SCRAM broker. Use **separate disposable databases**, not a single all-ignored invocation: auth tests leave valid outbox intents, while outbox ordering tests deliberately inspect the global pending head. The test database role needs schema creation privileges.

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo audit --deny warnings
TEST_DATABASE_URL="$IDENTITY_TEST_DB" cargo test --locked \
  --test auth_security --test authorization_race --test mfa_migration \
  --test mfa_password --test oauth_security --test rekey \
  -- --include-ignored --test-threads=1
cargo test --locked --test signing --test signing_formats \
  -- --include-ignored --test-threads=1
TEST_DATABASE_URL="$OUTBOX_TEST_DB" cargo test --locked --test outbox_security \
  -- --include-ignored --test-threads=1 \
  --skip relay_publishes_canonical_key_trace_and_aggregate_order_to_real_kafka
TEST_DATABASE_URL="$RELAY_TEST_DB" cargo test --locked --test outbox_security \
  relay_publishes_canonical_key_trace_and_aggregate_order_to_real_kafka \
  -- --include-ignored --test-threads=1
TEST_EMPTY_DATABASE_URL="$EMPTY_TEST_DB" cargo test --locked --test readiness \
  -- --include-ignored
```

The relay database starts fresh and the broker must expose actual six-partition topics over authenticated TLS. The empty database is intentionally left unmigrated. The migration regression temporarily changes its process environment and must run serially. OpenSSL is a test-only external verifier/fixture generator, not part of the production image.

The dependency changes and added metrics/HTTPS-chain/CA-import regressions require a fresh controller run of the commands above, including every ignored signing/format test and the real PostgreSQL/Kafka regressions. Earlier local evidence does not certify the regenerated dependency graph. Audit the full committed Cargo.lock without advisory ignores or package filtering, then rebuild and scan the final image.

Remote GitHub CI has **not** been executed or published by the local controller. Identity CI requires repository variable `PLATFORM_CONTRACTS_REVISION` or dispatch input `contracts_revision` containing an approved immutable 40-character lowercase commit SHA; missing/branch/tag values fail closed. CI records both source revisions. A local uncommitted contracts tree must not be represented as a remotely published revision. External Telegram credentials remain an explicit acceptance prerequisite.
CI fetches complete service history and scans it with redacted Gitleaks output before installing dependencies or generating credentials; the pinned contracts tree is scanned separately. Checkout credentials are not persisted. Disposable private keys are owner-readable only, generated tokens are masked before environment export, and broker/credential cleanup runs on success or failure. The database and authenticated TLS/SCRAM relay checks remain real, isolated dependencies, not mocks. First publication must use push/PR checks; manual dispatch is available once the workflow is on `main`.
CI also exports the final scratch image by its inspected image ID and scans that actual archive with digest-pinned Trivy across every vulnerability severity. The gate verifies matching report ImageID and a nonzero package inventory; source Cargo audit alone is not accepted as final-artifact proof. Raw reports remain private in the runner temp directory and are cleaned without upload.

Domain authorization/grant policies and transaction/publisher ports are orchestrated by application modules with PostgreSQL/Kafka adapters and HTTP mapping. Sensitive authority is rechecked under user→session locks after hashing; challenge locks follow user locks. Spent-code revocation proves exact redirect and PKCE before destructive state change and emits an atomic outbox record.
