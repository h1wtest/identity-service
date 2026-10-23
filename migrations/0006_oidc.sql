-- Only hashes of bearer credentials are retained. Consumed grants remain available
-- for replay detection until their source session is removed.
CREATE TABLE oauth_token_families (
    id UUID PRIMARY KEY,
    client_id VARCHAR(100) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    nonce TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT
);
CREATE INDEX oauth_token_families_session ON oauth_token_families(session_id);

CREATE TABLE oauth_authorization_codes (
    code_hash TEXT PRIMARY KEY,
    client_id VARCHAR(100) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    nonce TEXT,
    code_challenge TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    family_id UUID REFERENCES oauth_token_families(id) ON DELETE CASCADE
);
CREATE INDEX oauth_authorization_codes_session ON oauth_authorization_codes(session_id);

CREATE TABLE oauth_refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    family_id UUID NOT NULL REFERENCES oauth_token_families(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);
CREATE INDEX oauth_refresh_tokens_family ON oauth_refresh_tokens(family_id);

-- The browser registration is public and has no client secret. Redirect matching
-- is exact; deployments with a different public origin update this registration
-- explicitly during their bootstrap rather than allowing URI wildcards.
INSERT INTO oauth_clients(client_id,client_name,redirect_uris,allowed_scopes,is_public)
VALUES ('web-demo','SSO browser OIDC client',ARRAY['https://localhost:8448/oidc/callback'],ARRAY['openid','email','profile','offline_access'],true)
ON CONFLICT (client_id) DO UPDATE SET
    client_secret_hash=NULL,
    redirect_uris=EXCLUDED.redirect_uris,
    allowed_scopes=EXCLUDED.allowed_scopes,
    is_public=true,
    updated_at=NOW();
