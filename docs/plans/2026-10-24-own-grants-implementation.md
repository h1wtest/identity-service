# S03 own OAuth grants completion

Approved by integration owner: complete previously approved own-grant management, no separate design expansion.

## Files/interfaces
- tests/oauth_security.rs: first author real PostgreSQL/router own list/revoke regression; parent runs RED before implementation. Tests existing authorization code/PKCE, consent/family persistence, immediate access+refresh revoke, other-user/client/session isolation, missing grant_id rejection and paginated own listing.
- src/oauth.rs: GET /api/v1/auth/oauth/grants?limit=1..100(default50)&cursor=opaque -> {items:[{client_id,client_name,scopes,trusted_first_party,granted_at,last_used_at}],next_cursor:null|string}; DELETE /api/v1/auth/oauth/grants/{client_id} -> {client_id,revoked:true}. Own live actor, browser CSRF/Origin mutations. Client row then user/session lock, own consent removal/family revoke/unconsumed-code expiry/pending-consent consumption same transaction. Repeated unknown/foreign scoped target returns same idempotent true without disclosing grant presence. Preserve history, other users/clients, platform session.
- src/security.rs and src/application/oauth.rs: optional typed Claims.grant_id accommodates ID/platform token representations; OAuth access issuance sets family UUID; ID tokens omit it. OIDC authentication requires nonempty grant_id and matching live authoritative family/client/user/session. Pre-cutover OAuth access without grant_id rejected (explicit clean cutover), no legacy marker/shim or extra migration.
- Update all owned Claims literal callers/tests, README/CHANGELOG and local report. Existing tables sufficient, no migration.

## Ordering/security
Use existing client FOR UPDATE before user/session/family ordering shared token redemption and owner client revoke. Own GET keyset client_id lexical, bounded limit+1, opaque base64 URL-safe cursor decode with bounded canonical client text. No cross-database calls. Fresh password/MFA not required for ordinary own-resource revoke; existing actor/session/CSRF still enforced.

## Parent verification
Run new named oauth_security regression RED first, then parent cargo fmt/clippy/full tests and actual PostgreSQL suites after implementation; real browser own grants revoke/reauthorize acceptance. Worker runs no checks/builds and publishes nothing.
