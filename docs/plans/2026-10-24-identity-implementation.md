# Identity platform implementation plan

**Goal:** Preserve authentication/OIDC while adding authoritative OWNER/ADMIN/SUPPORT policy, owner role/client administration, session UX metadata, registration attribution and v2 contracts.
**Architecture:** Extend existing Axum/SQLx transactions, authorization ports and outbox. Append migrations only; serialize privileged mutations with a shared advisory lock and recheck live actor inside transaction. Existing OAuth grant/PKCE/reuse logic stays intact.
**Tech stack:** Pinned Rust 1.99, Axum 0.8, SQLx 0.9, PostgreSQL, existing contracts, rustls and Argon2.

## Constraints
Only this isolated identity repo; no publication/cloud/production. No checks/build/tests/formatters during worker implementation. Regression tests are authored before implementation; integration owner exercises them after the wave. Never alter applied migration bytes. No frontend changes.

## Steps and files
1. Add behavioral regression suite `tests/generic_identity.rs`: intrinsic self policy, code-owned permissions, last-owner simultaneous demotions, ordinary-user-only support revocation, current-first expiry/UA/session listing without activity mutation, reauth/owner-only client registration, exact redirects/consent, registration v2 metadata. Real HTTP router and disposable PostgreSQL fixtures, no source-text assertions.
2. Append `migrations/0008_generic_identity.sql`: rename super_admin to owner, remove user bindings/obsolete permissions, seed exact permission catalog and persisted role maps, roles version, owner mutation audit, registration metadata, client trusted/revoked flags, durable consent requests/consents and aggregate event counters. Keep existing grants/sessions/users intact.
3. Add `src/rbac.rs` and route via `src/lib.rs`: GET roles/permissions, PUT role permissions, GET/PUT user staff roles. OWNER invariant checked separately from editable map; password reauth <=5min plus MFA <=15min for role/client writes; advisory lock before user locks prevents concurrent last-owner demotion/ban.
4. Extend `src/auth.rs`, `src/auth/internal.rs`, postgres security adapter: intrinsic own-resource permissions; known administrative permissions require enabled/fresh MFA; service-specific scoped introspection v2; direct administrative user/session routes; support only ordinary-user session revoke with reason; current-first session metadata, authentic activity rate-limited 60s but no touch on listing, revoke-others. Append live authorization checks, don't trust stale role labels.
5. Add `src/oauth_admin.rs`, extend OAuth transport/adapter: OWNER list/register/rotate/revoke clients; exact HTTPS redirect and bounded supported scopes, one-time Argon2 secret; third-party durable same-session consent with explicit confirm/deny and CSRF, trusted first-party bypass only explicit policy; revoked client cannot issue/use tokens. Preserve code/refresh PKCE and replay semantics.
6. Extend config and registration: optional EN/RU locale/referral_code; only provided code causes bounded CA-verified no-redirect HTTPS referral prepare; persist registration_id/claim and emit validated typed v2 event. Add referral scoped paginated historical identity backfill. Produce v2 all events while retained existing v1 outbox drains unchanged.
7. Update `.env.example`, existing Docker/config documentation, README and changelog. Write `local://generic-identity-report.md` with exact API/config and parent check commands.

## Parent verification commands
`cargo fmt --check`; `cargo test --locked`; disposable TEST_DATABASE_URL/full identity env `cargo test --locked --test generic_identity -- --ignored --test-threads=1`; existing ignored auth/OAuth/race suites. Exercise full local HTTPS identity/referral registration, role/client mutation authorization, third-party consent/code/refresh/reuse and v1 outbox drain using integration stand. Worker does not execute checks.
