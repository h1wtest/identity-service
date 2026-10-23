-- SPDX-License-Identifier: MIT
-- Preserve migration0008 bytes after integration DB application.
ALTER TABLE outbox_events DROP CONSTRAINT outbox_canonical_envelope;
ALTER TABLE outbox_events ADD CONSTRAINT outbox_canonical_envelope CHECK(
    (topic IS NULL AND is_processed) OR COALESCE(
        payload->>'event_id'=id::text AND payload->>'event_type'=event_type
        AND payload->>'aggregate_id'=aggregate_id AND payload ? 'occurred_at'
        AND (
            (payload->>'schema_version'='1' AND (
                (topic='notification.commands.v1' AND event_type IN ('notification.email_verification','notification.password_reset') AND payload ? 'encrypted_payload' AND NOT payload ? 'payload')
                OR (topic='identity.events.v1' AND event_type LIKE 'identity.%' AND payload ? 'payload' AND NOT payload ? 'encrypted_payload')
            ))
            OR (payload->>'schema_version'='2' AND payload->>'producer'='identity' AND (payload->>'aggregate_version')::bigint>0 AND (
                (topic='notification.commands.v2' AND payload->>'aggregate_type'='delivery_command' AND aggregate_id=id::text AND payload->>'aggregate_version'='1' AND event_type IN ('notification.email_verification','notification.password_reset') AND payload ? 'encrypted_payload' AND NOT payload ? 'payload')
                OR (topic='identity.events.v2' AND payload->>'aggregate_type'='user' AND event_type LIKE 'identity.%' AND payload ? 'payload' AND NOT payload ? 'encrypted_payload')
                OR (topic='identity.events.v2' AND event_type='identity.admin_action_recorded' AND payload->>'aggregate_type'='identity_admin_action' AND aggregate_id=id::text AND payload->>'aggregate_version'='1' AND payload->'payload'->>'audit_id'=id::text AND payload ? 'payload' AND NOT payload ? 'encrypted_payload')
            ))
        ),false)
);
ALTER TABLE oauth_clients ALTER COLUMN client_name TYPE VARCHAR(200);
