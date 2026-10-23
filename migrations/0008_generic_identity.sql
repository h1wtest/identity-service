-- Additive cutover; all preceding migration bytes remain immutable.
UPDATE roles SET slug='owner',name='OWNER' WHERE slug='super_admin';
UPDATE roles SET name=upper(slug) WHERE slug IN ('admin','support');
DELETE FROM user_roles WHERE role_id IN (SELECT id FROM roles WHERE slug='user');
DELETE FROM roles WHERE slug='user';
ALTER TABLE roles ADD COLUMN version BIGINT NOT NULL DEFAULT 1;
DELETE FROM role_permissions;
DELETE FROM permissions;
INSERT INTO permissions(id,slug,module,description)
SELECT ('018f0000-0002-7000-8000-'||lpad(n::text,12,'0'))::uuid,slug,split_part(slug,':',1),slug
FROM unnest(ARRAY['users:read','users:write','users:sessions:revoke','roles:read','roles:write','roles:assign','catalog:read','catalog:write','catalog:publish','billing:read','billing:resolve','subscriptions:read','subscriptions:write','subscriptions:compensate','subscriptions:close','referrals:read','referrals:rates:write','referrals:payouts:decide','notifications:read','notifications:templates:write','notifications:replay','notifications:bindings:reset','audit:read','oauth:clients:write']) WITH ORDINALITY AS p(slug,n);
INSERT INTO role_permissions SELECT r.id,p.id FROM roles r CROSS JOIN permissions p WHERE r.slug='owner' OR (r.slug='admin' AND p.slug NOT LIKE 'roles:%' AND p.slug<>'oauth:clients:write') OR (r.slug='support' AND p.slug IN ('users:read','users:sessions:revoke','catalog:read','billing:read','subscriptions:read','notifications:read'));
ALTER TABLE users ADD COLUMN registration_id UUID;
UPDATE users SET registration_id=id;
ALTER TABLE users ALTER COLUMN registration_id SET NOT NULL;
ALTER TABLE users ADD COLUMN registration_locale TEXT NOT NULL DEFAULT 'en' CHECK(registration_locale IN ('en','ru'));
ALTER TABLE users ALTER COLUMN registration_id SET DEFAULT gen_random_uuid();
ALTER TABLE users ADD COLUMN referral_claim_id UUID;
CREATE UNIQUE INDEX users_registration_id ON users(registration_id);
ALTER TABLE oauth_clients ADD COLUMN trusted_first_party BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE oauth_clients ADD COLUMN revoked_at TIMESTAMPTZ;
-- The bundled public browser registration is the explicitly configured first party.
UPDATE oauth_clients SET trusted_first_party=true WHERE client_id='web-demo';
CREATE TABLE identity_admin_audit(id UUID PRIMARY KEY,actor_user_id UUID NOT NULL,actor_session_id UUID NOT NULL,operation TEXT NOT NULL,target TEXT NOT NULL,reason TEXT NOT NULL,details JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE identity_aggregate_versions(aggregate_id UUID PRIMARY KEY,version BIGINT NOT NULL CHECK(version>0));
CREATE TABLE oauth_consent_requests(id UUID PRIMARY KEY,user_id UUID NOT NULL REFERENCES users(id),session_id UUID NOT NULL REFERENCES sessions(id),client_id VARCHAR(100) NOT NULL REFERENCES oauth_clients(client_id),request JSONB NOT NULL,scopes TEXT[] NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),expires_at TIMESTAMPTZ NOT NULL DEFAULT now()+interval '10 minutes',consumed_at TIMESTAMPTZ);
CREATE TABLE oauth_consents(user_id UUID NOT NULL REFERENCES users(id),client_id VARCHAR(100) NOT NULL REFERENCES oauth_clients(client_id),scopes TEXT[] NOT NULL,updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),PRIMARY KEY(user_id,client_id));
ALTER TABLE oauth_consent_requests ADD COLUMN approved BOOLEAN;
ALTER TABLE users ADD COLUMN role_version BIGINT NOT NULL DEFAULT 1;
CREATE TABLE identity_admin_commands(command_id UUID PRIMARY KEY,actor_user_id UUID NOT NULL,operation TEXT NOT NULL,target UUID NOT NULL,request JSONB NOT NULL,result JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now());
INSERT INTO role_permissions SELECT r.id,p.id FROM roles r CROSS JOIN permissions p WHERE r.slug='support' AND p.slug='notifications:bindings:reset' ON CONFLICT DO NOTHING;
INSERT INTO permissions(id,slug,module,description) VALUES('018f0000-0002-7000-8000-000000000025','billing:status:read','billing','Read safe payment status');
INSERT INTO role_permissions SELECT r.id,p.id FROM roles r CROSS JOIN permissions p WHERE p.slug='billing:status:read';
DELETE FROM role_permissions WHERE role_id=(SELECT id FROM roles WHERE slug='support') AND permission_id=(SELECT id FROM permissions WHERE slug='billing:read');
-- Explicit retained-v1 drain plus new v2 producer; never rewrite stored event IDs.
ALTER TABLE outbox_events DROP CONSTRAINT outbox_topic_allowed;
ALTER TABLE outbox_events DROP CONSTRAINT outbox_canonical_envelope;
ALTER TABLE outbox_events ADD CONSTRAINT outbox_topic_allowed CHECK((topic IS NULL AND is_processed) OR COALESCE(topic IN ('identity.events.v1','notification.commands.v1','identity.events.v2','notification.commands.v2'),false));
ALTER TABLE outbox_events ADD CONSTRAINT outbox_canonical_envelope CHECK((topic IS NULL AND is_processed) OR COALESCE(
    payload->>'event_id'=id::text AND payload->>'event_type'=event_type AND payload->>'aggregate_id'=aggregate_id AND payload ? 'occurred_at'
    AND ((payload->>'schema_version'='1' AND ((topic='notification.commands.v1' AND event_type IN ('notification.email_verification','notification.password_reset') AND payload ? 'encrypted_payload' AND NOT payload ? 'payload') OR (topic='identity.events.v1' AND event_type LIKE 'identity.%' AND payload ? 'payload' AND NOT payload ? 'encrypted_payload')))
      OR (payload->>'schema_version'='2' AND payload->>'producer'='identity' AND (payload->>'aggregate_version')::bigint>0 AND ((topic='notification.commands.v2' AND payload->>'aggregate_type'='delivery_command' AND aggregate_id=id::text AND payload->>'aggregate_version'='1' AND event_type IN ('notification.email_verification','notification.password_reset') AND payload ? 'encrypted_payload' AND NOT payload ? 'payload') OR (topic='identity.events.v2' AND payload->>'aggregate_type'='user' AND event_type LIKE 'identity.%' AND payload ? 'payload' AND NOT payload ? 'encrypted_payload')))),false));
