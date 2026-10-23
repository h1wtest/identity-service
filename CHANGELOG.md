# Changelog

## Unreleased — platform remediation (2026-10-23)

### Security and behavior

- Replace Redis credential authority and unauthenticated gRPC with SQL-backed opaque Secure/HttpOnly sessions and authenticated TLS internal APIs. Enforce Origin, double-submit and session-bound CSRF, atomic ownership, live revoke/ban and fail-closed resource authorization.
- Separate pending and active MFA; require fresh reauthentication, consume challenges/TOTP steps/recovery codes once and preserve active factors during setup. Add bounded off-executor Argon2, persistent rate windows and transactional password recovery/change with session revocation.
- Implement RS256 OIDC discovery/JWKS, standard form token endpoint, S256 PKCE, exact HTTPS callbacks, nonce/scopes, confidential/public clients and atomic refresh rotation/reuse. Restrict client-audience tokens to OIDC userinfo. Prove PKCE before destructive spent-code handling.
- Recheck user-initiated logout/session revocation under the existing user→actor-session locks before mutating any target. Preserve consumed authorization-code replay detection beyond redemption expiry while always proving exact client/redirect/PKCE binding before revocation. Add deterministic database-lock HTTP revocation races, expired consumed-code revocation/event checks, and wrong-proof non-revocation coverage before and after expiry; controller verification remains required.
- Add MFA-gated bootstrap-admin CLI, migrations/readiness, purpose-separated encryption and explicit transactional legacy `rekey`; retain data and fail closed on unknown ciphertext.
- Commit canonical outbox events atomically, lease ordered aggregate heads, fence stale workers and publish to keyed six-partition Kafka through strict TLS/SCRAM. Encrypt sensitive commands before SQL persistence.
- Restore meaningful domain/application transaction and publisher ports with PostgreSQL/Kafka adapters; expose health, metrics and W3C/OTLP trace propagation.

### Packaging and verification

- Build a non-root musl-static scratch image using ring and audited PEM/DER parsers; embed the exact Cargo dependency inventory for meaningful vulnerability scanning. Pin build/toolchain/scanner dependencies and require immutable contract revisions in service CI.
- Fetch and redact-scan complete service history before dependency installation, separately scan the immutable contracts checkout, avoid persisted checkout credentials, mask generated environment credentials and clean owner-readable TLS/signing material plus the disposable broker on every exit path.
- Gate the actual final image archive on zero vulnerabilities at every severity, matching built/scanned image IDs and a nonzero package inventory; keep and clean scan reports privately without upload.
- Replace Prometheus 0.13.4/protobuf 2.28.0 with maintained Prometheus 0.14.0 text-only encoding; keep `/metrics` text counters, latency histograms and gauges. Upgrade SQLx 0.8.6 to 0.9.0 with PostgreSQL-only active features and explicit macros/migrations; its default-disabled MySQL RSA feature removes vulnerable rsa 0.9.10 from the regenerated Cargo.lock. Cargo still records optional driver metadata because of upstream weak-feature lockfile behavior.
- Upgrade axum-server 0.7.3 to 0.8.0 and replace direct rustls-pemfile 2.2.0 CA parsing with rustls-pki-types 1.15.1 `PemObject`; remove the unmaintained parser transitively and directly. Preserve PKCS1/PKCS8 HTTPS/signing and SPKI/PKCS1 rotation behavior without changing authentication flows. Add text-metrics, real in-memory TLS handshake/chain, mismatched-key and strict Kafka CA import regressions; verification of this dependency graph remains a controller gate, not a claimed pass.
- Local controller evidence: strict Clippy, non-DB checks, 36 selected real PostgreSQL regressions, rekey, real TLS/SCRAM relay and six signing/import/rotation tests passed. Strict HTTPS/Mailpit/Kafka/profile/session/MFA/password/OIDC flows and real-browser OIDC were exercised. Static linkage was inspected and the inventory-aware final-image scan reported zero HIGH/CRITICAL findings.
- Tests requiring PostgreSQL use separate identity/outbox/relay/empty databases as documented. Remote CI publication, production readiness, OIDC certification and genuine Telegram delivery are not claimed.
