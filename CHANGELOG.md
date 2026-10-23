# Changelog

## Unreleased — platform remediation (2026-10-23)

### Security and behavior

- Replace Redis credential authority and unauthenticated gRPC with SQL-backed opaque Secure/HttpOnly sessions and authenticated TLS internal APIs. Enforce Origin, double-submit and session-bound CSRF, atomic ownership, live revoke/ban and fail-closed resource authorization.
- Separate pending and active MFA; require fresh reauthentication, consume challenges/TOTP steps/recovery codes once and preserve active factors during setup. Add bounded off-executor Argon2, persistent rate windows and transactional password recovery/change with session revocation.
- Implement RS256 OIDC discovery/JWKS, standard form token endpoint, S256 PKCE, exact HTTPS callbacks, nonce/scopes, confidential/public clients and atomic refresh rotation/reuse. Restrict client-audience tokens to OIDC userinfo. Prove PKCE before destructive spent-code handling.
- Add MFA-gated bootstrap-admin CLI, migrations/readiness, purpose-separated encryption and explicit transactional legacy `rekey`; retain data and fail closed on unknown ciphertext.
- Commit canonical outbox events atomically, lease ordered aggregate heads, fence stale workers and publish to keyed six-partition Kafka through strict TLS/SCRAM. Encrypt sensitive commands before SQL persistence.
- Restore meaningful domain/application transaction and publisher ports with PostgreSQL/Kafka adapters; expose health, metrics and W3C/OTLP trace propagation.

### Packaging and verification

- Build a non-root musl-static scratch image using ring and audited PEM/DER parsers; embed the exact Cargo dependency inventory for meaningful vulnerability scanning. Pin build/toolchain/scanner dependencies and require immutable contract revisions in service CI.
- Fetch and redact-scan complete service history before dependency installation, separately scan the immutable contracts checkout, avoid persisted checkout credentials, mask generated environment credentials and clean owner-readable TLS/signing material plus the disposable broker on every exit path.
- Gate the actual final image archive on zero vulnerabilities at every severity, matching built/scanned image IDs and a nonzero package inventory; keep and clean scan reports privately without upload.
- Local controller evidence: strict Clippy, non-DB checks, 36 selected real PostgreSQL regressions, rekey, real TLS/SCRAM relay and six signing/import/rotation tests passed. Strict HTTPS/Mailpit/Kafka/profile/session/MFA/password/OIDC flows and real-browser OIDC were exercised. Static linkage was inspected and the inventory-aware final-image scan reported zero HIGH/CRITICAL findings.
- Tests requiring PostgreSQL use separate identity/outbox/relay/empty databases as documented. Remote CI publication, production readiness, OIDC certification and genuine Telegram delivery are not claimed.
