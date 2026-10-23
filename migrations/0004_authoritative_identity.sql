-- Never mutate historical migrations: retain users and old audit/session history.
ALTER TABLE sessions ADD COLUMN cookie_hash TEXT UNIQUE;
ALTER TABLE sessions ADD COLUMN csrf_hash TEXT;
ALTER TABLE sessions ADD COLUMN mfa_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE sessions ADD COLUMN mfa_verified_at TIMESTAMPTZ;
ALTER TABLE sessions ADD COLUMN reauthenticated_at TIMESTAMPTZ;
-- Legacy Redis-only credentials cannot become authoritative SQL credentials.
UPDATE sessions SET is_active=FALSE,revoked_reason='authoritative_session_migration' WHERE cookie_hash IS NULL;
ALTER TABLE mfa_secrets ADD COLUMN last_used_step BIGINT NOT NULL DEFAULT -1;
CREATE TABLE pending_mfa (
 user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
 encrypted_secret TEXT NOT NULL,
 recovery_hashes TEXT[] NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE identity_challenges (
 id UUID PRIMARY KEY,
 user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK(kind IN ('verify_email','password_reset','mfa_login')),
 token_hash TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 metadata JSONB NOT NULL DEFAULT '{}',
 expires_at TIMESTAMPTZ NOT NULL,
 consumed_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX identity_challenges_token ON identity_challenges(kind,token_hash);
CREATE INDEX identity_challenges_user ON identity_challenges(user_id,kind);
CREATE TABLE identity_rate_limits (
 bucket TEXT PRIMARY KEY,
 window_start TIMESTAMPTZ NOT NULL,
 attempts INTEGER NOT NULL
);
-- Restricted implemented permissions only; historical definitions remain for audit.
INSERT INTO permissions(id,slug,module,description) VALUES
 ('018f0000-0001-7000-8000-000000000021','users:write','admin','Ban and unban accounts'),
 ('018f0000-0001-7000-8000-000000000022','audit:read','admin','Read sanitized audit'),
 ('018f0000-0001-7000-8000-000000000023','deliveries:read','admin','Read delivery history'),
 ('018f0000-0001-7000-8000-000000000024','deliveries:replay','admin','Replay terminal deliveries')
ON CONFLICT(slug) DO NOTHING;
INSERT INTO role_permissions(role_id,permission_id)
 SELECT r.id,p.id FROM roles r CROSS JOIN permissions p
 WHERE r.slug IN ('admin','super_admin') AND p.slug IN ('users:read','users:write','audit:read','deliveries:read','deliveries:replay')
ON CONFLICT DO NOTHING;
