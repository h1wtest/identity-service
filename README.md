# Identity service

Rust/Axum identity owner. PostgreSQL is authoritative for users, sessions, MFA challenges, recovery, OAuth grants and the transactional outbox. No Redis credential authority, shared HMAC JWT secret, unauthenticated gRPC endpoint or client-supplied user identity remains.

## Commands and deployment

Use the isolated platform-infra bootstrap, which generates credentials and TLS/RSA keys outside Git. Build from the workspace root:

```sh
docker build -f identity-service/Dockerfile -t identity-service:<source-sha> .
```

The final image is `scratch`: a musl-static Rust executable and the pinned-builder CA bundle, running uid 10001 without shell or shared system libraries. Build targets `x86_64-unknown-linux-musl`; this local platform image is AMD64, not a claim of verified ARM64 support. RSA key validation/public derivation uses ring; JWT signatures use jsonwebtoken's AWS-LC backend, with audited PEM/PKCS1/SPKI DER parsers and no custom RSA arithmetic. OpenSSL is not a runtime/dependency requirement. Builder apt uses a fixed Debian snapshot and strict error mode; its CMake/musl toolchain builds AWS-LC statically. Verify the actual binary with `file`/`ldd`; the scratch base alone does not establish dependency safety. Vulnerability scanning was removed by the owner; do not run dependency or image vulnerability scanners.


The checked-in `rust-toolchain.toml` pins Rust 1.99.0. Cargo.lock is the dependency authority; builds use `--locked`. Empty secrets fail closed. `MFA_ENCRYPTION_KEY` (identity only) and distinct `DELIVERY_ENCRYPTION_KEY` (identity and notification worker only) are independent base64 32-byte keys. Caller credentials and `GATEWAY_INTERNAL_TOKEN` are distinct random strings of at least 32 characters. TLS is mandatory on port 8001. Gateway authentication protects forwarded client IP; untrusted requests use socket peer IP. Kafka requires CA/hostname verification and SCRAM-SHA256 using `KAFKA_TLS_CA_FILE`, `KAFKA_SASL_USERNAME`, `KAFKA_SASL_PASSWORD`, without plaintext fallback. Mount keys as uid 10001. Keep previous public signing key and distinct kid while old tokens expire, never distribute its private key.

Dependency remediation uses SQLx **0.9.0** with `default-features = false` and explicit PostgreSQL, Tokio/rustls-ring, UUID/chrono/JSON, macros and migration support. The active driver is PostgreSQL only; no MySQL authentication or `rsa` crate is used. Cargo's [weak-feature lockfile issue](https://github.com/transact-rs/sqlx/issues/3211) still records optional `sqlx-mysql`/`sqlx-sqlite` 0.9.0 metadata, so lockfile presence alone is not proof a driver is compiled. Unlike 0.8.6, the maintained 0.9.0 MySQL dependency does not enable RSA by default. SQLx migrations remain embedded with `sqlx::migrate!`; prepared statements, checksums and transactional authorization are unchanged. Test-only dynamic schema identifiers are locally generated UUIDs and explicitly marked `AssertSqlSafe` for SQLx 0.9.

Prometheus **0.14.0** disables unused default protobuf encoding: `/metrics` continues to serve Prometheus **text/plain; version=0.0.4**, including counters, latency histogram buckets/sum/count and operational gauges. This removes protobuf 2.28.0 rather than waiving RUSTSEC-2024-0437; binary protobuf metrics were never exposed. HTTPS uses axum-server **0.8.0**, whose PEM loader uses maintained `rustls-pki-types`; the direct Kafka CA loader uses `CertificateDer::pem_slice_iter` from resolved `rustls-pki-types` **1.15.1**. `rustls-pemfile` is no longer a dependency. HTTPS certificate chains and PKCS1/PKCS8 RSA keys remain supported; signing/JWKS still supports PKCS1/PKCS8 private keys and PKCS1/SPKI previous public keys through the existing ring/DER path. Empty, malformed or invalid Kafka CA material fails before a broker connection; hostname/CA verification and SCRAM remain mandatory.

The final-image findings additionally require jsonwebtoken **10.4.0** (patched floor **10.3.0** for [CVE-2026-25537](https://github.com/Keats/jsonwebtoken/security/advisories/GHSA-h395-gr6q-cpjc)) and opentelemetry_sdk **0.32.1** ([CVE-2026-48504](https://github.com/open-telemetry/opentelemetry-rust/security/advisories/GHSA-w9wp-h8wv-79jx)). JWT enables only `aws_lc_rs` and PEM import, not the `rust_crypto` backend that would restore vulnerable `rsa`; RS256, kid/issuer checks and key formats remain unchanged. The claim advisory concerns malformed optional standard claims; this service already requires typed expiry, and its signed malformed-expiry regression remains fail-closed. Telemetry uses matching OpenTelemetry/OTLP **0.32.0** and tracing-opentelemetry **0.33.0**, retaining W3C TraceContext, service resources, three-second OTLP HTTP/protobuf timeout and Tokio asynchronous batch export. The optional exporter uses an explicit async processor with the async reqwest client rather than the SDK's new blocking-client defaults. The baggage advisory affects oversized `BaggagePropagator` headers; this service installs only TraceContext propagation, but still upgrades the SDK rather than suppressing the finding. A real local HTTP collector regression covers completed-span export and original trace ID propagation. Full tests and an immutable-image rebuild remain required for this graph; vulnerability scanning was removed by the owner.

```sh
# Fresh schema needs DATABASE_URL only; legacy MFA additionally requires the new identity-only key.
DATABASE_URL="$IDENTITY_MIGRATION_URL" MFA_ENCRYPTION_KEY="$MFA_KEY" identity-service migrate
# All regular runtime settings must also be supplied for bootstrap.
OWNER_EMAIL="$EMAIL" OWNER_PASSWORD="$PASSWORD" identity-service bootstrap-owner
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

Bootstrap is serialized/idempotent for an existing OWNER, preserves its password and refuses silent non-owner elevation. It configures only bundled web-demo's exact callback from PUBLIC_ORIGIN (/oidc/callback), including repeat bootstrap; other clients/grants remain intact. Administrative operations require enabled MFA verified within15minutes; role/client mutations additionally require password reauthentication within5minutes. Migration0008 maps super_admin to owner and removes user staff bindings in favor of intrinsic own-resource permissions.

## Browser and internal API

Browser session `sso_session` is opaque, HttpOnly, Secure, SameSite=Lax and stored as a SHA-256 hash in SQL. `GET /api/v1/auth/csrf` sets a readable Secure `sso_csrf`. Every browser mutation requires exact `Origin: PUBLIC_ORIGIN`, matching `X-CSRF-Token` and cookie; authenticated mutations additionally match the authoritative session hash. A SPA reload calls `/api/v1/auth/me`. Logout, revoke, password change/reset and ban immediately invalidate SQL sessions, including previously signed OAuth tokens. A session cannot be revoked by another user.

Auth endpoints implement registration/email verification, login/MFA challenge, `/sessions`, `/reauth`, pending MFA setup/enable/disable, password forgot/reset/change. Passwords are 12–1024 bytes, Argon2id runs off the async executor behind four permits. Persistent SQL rate windows cover authentication/recovery operations. Email is normalized, errors are redacted `{error,code}`, dependency failure is 503 and never authenticates. Recovery replies do not disclose whether an account exists; delivery credentials are encrypted before SQL outbox insertion. TOTP steps and recovery codes are consumed once under row locks. A failed or abandoned setup never changes an active secret.

Internal callers use HTTPS and distinct X-Service-Token; unknown/empty tokens are denied. New owners use /internal/v2/introspect with current actor credentials, original HTTP method/Origin/CSRF and permission. Catalog/billing/subscription/referral credentials are scoped to their own permission family; all administrative permissions enforce fresh MFA regardless of caller flags. users:self:reauth is a virtual own-resource password-fresh decision, not staff permission. Response includes is_verified and nullable reauthenticated_at. Retained v1 introspection/admin handlers are explicit compatibility-window adapters, not the new transport.

## OAuth/OIDC

Discovery, JWKS and OAuth endpoints preserve S256 PKCE, exact HTTPS redirects, state/nonce, confidential/public authentication and code/refresh reuse semantics. OWNER manages /api/v1/admin/oauth/clients: list/register, rotate confidential secret and revoke. Secrets are shown once and Argon2id-hashed; audit excludes secrets. Supported scopes are bounded; redirects reject wildcards/credentials/fragments. Trusted first-party is explicit. Third-party clients require durable same-user/same-session10-minute consent GET/POST /api/v1/auth/oauth/consent/{id}, then safe same-origin /oauth/consent/complete/{id} performs the validated external client redirect. Denial returns access_denied; prompt=none returns consent_required. Revoked clients cannot authorize/redeem or use userinfo. No OIDC certification is claimed.
Client-audience OIDC tokens authorize only `/oauth/userinfo`, never management/admin/Go resource APIs even with an ambient cookie. Those APIs accept browser sessions or resource tokens with `aud=PUBLIC_ORIGIN` and `platform:api`; no public resource-token grant is issued without an explicit client authorization policy.


## Outbox and observability

New producers write validated v2 envelopes to identity.events.v2 and notification.commands.v2. Public user events have contiguous transactionally allocated versions; sensitive delivery_command aggregates use aggregate_id=event_id/version1 so other-topic events never create stream holes. Delivery AES-256-GCM retains event UUID AAD; MFA uses distinct identity-only keys/user UUID AAD. Stored v1 rows retain IDs/bytes and drain to original topics through the dual-format relay. Operators prove v1 partition end-offsets/receipts drained before separately retiring compatibility handlers/ACL. Never delete retained events to force a green cutover.

Relay claims durable leases, never overtakes an older unprocessed event for the same aggregate, chooses one of exactly six partitions from aggregate UUID key and waits for broker acknowledgement before marking processed. Failure preserves a retriable row with bounded jitter; lease expiry recovers crashed workers. Delivery is at-least-once, not exactly-once. Kafka outage does not block login while PostgreSQL can commit the outbox. Monitor backlog age and provision capacity; no in-memory successful fallback exists.

`/health/live` is process liveness. `/health/ready` (also `/api/v1/auth/ready` for local acceptance) checks schema/dependencies; missing schema is never Ready. `/metrics` is internal-only via network/gateway policy and exposes HTTP counts/latency, SQL pool, readiness and outbox age/count. Structured logs do not contain credential bodies. HTTP W3C context is propagated into events and linked relay spans, with OTLP HTTP export when configured.

## Generic identity configuration and APIs

Generic configuration: CATALOG_INTERNAL_TOKEN, BILLING_INTERNAL_TOKEN, SUBSCRIPTION_INTERNAL_TOKEN, REFERRAL_INTERNAL_TOKEN and outbound IDENTITY_INTERNAL_TOKEN are distinct random32+ credentials. Missing new tokens disable that workload rather than accepting empty credentials; original-profile startup remains supported. Supplied referral_code additionally requires HTTPS REFERRAL_URL and mounted INTERNAL_CA_FILE. Client disables redirects, verifies CA/hostname, bounds timeout/body and never logs provider errors/secrets. No-code registration never calls referral; invalid/unavailable claim prevents registration. Locale en/ru, registration_id and nullable claim_id commit with the v2 registration event.

Existing pinned non-root static Docker image requires no additional executable. Mount internal CA read-only; apply migrations0008/0009 under migration credentials before runtime, otherwise readiness stays false. Migration0009 retains applied0008 bytes, permits sanitized audit-action envelopes and aligns client_name VARCHAR200 with public limits. Generic acceptance explicitly uses PUBLIC_ORIGIN/OAUTH_ISSUER=https://localhost:18448; original default8448 remains. OWNER_EMAIL/OWNER_PASSWORD are one-shot bootstrap inputs, never runtime-pod environment.

Direct identity role APIs /api/v1/admin/roles and /api/v1/admin/users/{id}/roles use expected_version (assignment GET returns role_version). OWNER map/owner-only permissions cannot be delegated. Shared advisory serialization plus live actor recheck protects concurrent last-owner demotion/ban and bootstrap. SUPPORT sees only billing:status:read, not provider evidence billing:read. Narrow notifications:bindings:reset cannot assign arbitrary chats.

Sessions list current-first with expiry/browser/os/device_label; unknown UA fields use unknown. Listing does not update activity. Other actual authenticated traffic updates at most once per60seconds. POST /api/v1/auth/sessions/revoke-others preserves current; existing DELETE one/all remains. Revocation persists OAuth-family revocation atomically. Administrative revocation requires reason/fresh MFA and current actor hierarchy: SUPPORT ordinary users only, ADMIN all except OWNER, OWNER any target. This does not relax last-owner ban/demotion protection.

Referral-only paginated /internal/v2/users exports historical registration IDs/claim/time. Scoped /users/{id}/eligibility checks live status. Notification-only flow and recipient discovery check current challenges/email/staff permission. Internal v2 admin ban/unban/revoke bodies require UUID idempotency_key; exact replay returns committed safe result, mismatch409. GET /internal/v2/admin/commands/{id} exposes only original actor's committed result; unknown404 is not success.

Role/client and direct administrative mutations atomically persist local audit plus typed identity.admin_action_recorded outbox records; safe actor/operation/target/reason fields asynchronously reach the audit projection without secrets or a synchronous audit-service dependency. Each audit action is an independent identity_admin_action aggregate (audit_id=event_id/version1) on identity.events.v2. Role assignment GET reads roles+role_version in one statement snapshot. OAuth code creation/redemption/refresh and consent acquire client row before user/session; rotate/revoke follow the same local ordering and recheck live client/secret snapshot, fencing stale pre-revoke requests while unrelated clients remain independent. Registration obtains one database clock_timestamp after enqueue waits, validates the claim deadline against it and persists that exact occurrence in users.created_at, registration event and backfill.

Fresh v2 identity credentials need Describe/Write only for identity.events.v2 and notification.commands.v2; relay startup does not require visibility of retained-v1 topics. Legacy rows drain only when present and their original publication is authorized; do not broaden current credentials merely to satisfy absent legacy metadata. Restricted transport regression requires dedicated KAFKA_V2_ONLY_USERNAME/PASSWORD (no legacy Describe ACL), authenticates actual TLS/SCRAM and publishes v2.


Profile's quarantine owner revalidates notifications:read/replay through its own workload credential; only those exact scopes plus notifications:bindings:reset are admitted. Profile cannot publish templates or resolve billing, and every administrative decision still requires current actor permissions/fresh MFA and owner checks.

Own connected applications use GET /api/v1/auth/oauth/grants (limit default50/max100, opaque keyset cursor) and DELETE /api/v1/auth/oauth/grants/{client_id}. List returns own approved client name/scopes/trusted policy/granted_at/last_used_at; no token or secret fields. Revoke is idempotent, requires live own session/Origin/CSRF, removes only own consent, expires own unspent codes/requests and revokes own client families without platform logout or other-account changes. Third-party authorization then requires consent again. OAuth access tokens now carry signed grant_id=family UUID; userinfo verifies the exact current family/client/user/session. Pre-cutover OAuth access without grant_id is deliberately rejected and requires reauthorization; ID tokens/platform resource sessions are unchanged, no compatibility shim or new schema. Code issuance rechecks live consent after the client lock so an old consent snapshot cannot recreate access after revoke.

New real PostgreSQL/router suite: TEST_DATABASE_URL="$IDENTITY_TEST_DB" cargo test --locked --test generic_identity -- --ignored --test-threads=1. Covers owner race, escalation denial, owner reauth/client secret, support restrictions, sessions, third-party consent and no-code/referral-outage registration. Worker executes no checks; controller must run formatting, clippy, complete existing/new tests and real HTTPS/OIDC integration after the shared wave.


## Verification and local acceptance

Historical scan evidence below predates the owner's removal of vulnerability scanning and is superseded as an active verification requirement; it is not a current vulnerability assessment.

The integration controller executed the following local checks after implementation: strict `cargo clippy --locked --all-targets -- -D warnings`; non-database tests; 36 selected PostgreSQL security/lease/readiness regressions, the rekey regression, the real TLS/SCRAM Kafka relay regression, and six RSA import/JWKS/signing/rotation regressions. These passed. The static-musl image was inspected with `file`/`readelf` (static PIE, no `INTERP`) and scanned with Trivy: the scanner detected its embedded Cargo.lock and reported zero HIGH/CRITICAL findings, rather than treating an empty scratch-image scan as evidence.

Strict HTTPS acceptance also passed against actual services: registration and Mailpit verification, keyed Kafka/profile projection, two-user ownership and CSRF denial, immediate revoke across identity/profile, OpenSSL-verified RS256/JWKS/nonce/state/PKCE OIDC and refresh reuse, MFA challenge/recovery replay protection, setup preserving the active factor, actual recovery email/reset token single-use, password change/revocation and logout. Real browser OIDC acceptance was exercised by the controller. This does not constitute OIDC certification, production acceptance, real Telegram delivery, or every broader platform fault/UI/observability gate.

To reproduce, supply full `.env.example` configuration with disposable credentials, generated RSA/TLS keys, distinct MFA/delivery keys and a verified TLS/SCRAM broker. Use **separate disposable databases**, not a single all-ignored invocation: auth tests leave valid outbox intents, while outbox ordering tests deliberately inspect the global pending head. The test database role needs schema creation privileges.

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
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

The dependency changes and added metrics/HTTPS-chain/CA-import regressions require a fresh controller run of the commands above, including every ignored signing/format test and the real PostgreSQL/Kafka regressions, followed by an immutable image rebuild. Earlier local evidence does not certify the regenerated dependency graph. Vulnerability scanning is not part of this verification.

Remote GitHub CI has **not** been executed or published by the local controller. Identity CI requires repository variable `PLATFORM_CONTRACTS_REVISION` or dispatch input `contracts_revision` containing an approved immutable 40-character lowercase commit SHA; missing/branch/tag values fail closed. CI records both source revisions. A local uncommitted contracts tree must not be represented as a remotely published revision. External Telegram credentials remain an explicit acceptance prerequisite.
CI fetches complete service history and scans it with redacted Gitleaks output before installing dependencies or generating credentials; the pinned contracts tree is scanned separately. Checkout credentials are not persisted. Disposable private keys are owner-readable only, generated tokens are masked before environment export, and broker/credential cleanup runs on success or failure. The database and authenticated TLS/SCRAM relay checks remain real, isolated dependencies, not mocks. First publication must use push/PR checks; manual dispatch is available once the workflow is on `main`.
CI builds the immutable scratch image with service and contracts source-revision labels without publishing. Dependency and final-image vulnerability scanning, scanner-only archive/report generation and scanner-only cleanup were removed by owner instruction. Full-history secret scanning, genuine tests, source provenance, credential/broker cleanup and existing patched dependencies remain; scanner removal does not establish zero vulnerabilities.

Domain authorization/grant policies and transaction/publisher ports are orchestrated by application modules with PostgreSQL/Kafka adapters and HTTP mapping. Sensitive authority is rechecked under user→session locks after hashing; challenge locks follow user locks. Spent-code revocation proves exact redirect and PKCE before destructive state change and emits an atomic outbox record.
