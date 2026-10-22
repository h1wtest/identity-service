-- =============================================================
-- OAuth 2.1 / OIDC Clients table
-- =============================================================
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id VARCHAR(100) PRIMARY KEY,
    client_secret_hash VARCHAR(255),
    client_name VARCHAR(100) NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    allowed_scopes TEXT[] NOT NULL,
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed initial trusted client (Frontend SPA with PKCE)
INSERT INTO oauth_clients (
    client_id, client_secret_hash, client_name, redirect_uris, allowed_scopes, is_public
) VALUES (
    'trade_helper_frontend',
    NULL,
    'Trade Helper Web Client',
    ARRAY['http://localhost:3000/callback', 'http://127.0.0.1:3000/callback'],
    ARRAY['openid', 'profile', 'email'],
    TRUE
)
ON CONFLICT (client_id) DO NOTHING;
