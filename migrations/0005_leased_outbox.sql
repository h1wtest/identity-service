-- Durable at-least-once claims; the predecessor remains pending throughout retry/lease.
ALTER TABLE outbox_events ADD COLUMN sequence BIGSERIAL;
ALTER TABLE outbox_events ADD COLUMN topic TEXT;
ALTER TABLE outbox_events ADD COLUMN lease_token UUID;
ALTER TABLE outbox_events ADD COLUMN lease_until TIMESTAMPTZ;
ALTER TABLE outbox_events ADD COLUMN next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Do not silently discard or publish incompatible legacy protobuf delivery intents.
-- Drain pending old intents before switching; processed historical rows remain untouched.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM outbox_events WHERE NOT is_processed) THEN
        RAISE EXCEPTION 'drain legacy outbox before applying canonical event migration';
    END IF;
END; $$;
ALTER TABLE outbox_events ADD CONSTRAINT outbox_topic_allowed CHECK ((topic IS NULL AND is_processed) OR COALESCE(topic IN ('identity.events.v1','notification.commands.v1'),false));
ALTER TABLE outbox_events ADD CONSTRAINT outbox_lease_pair CHECK ((lease_token IS NULL) = (lease_until IS NULL));
ALTER TABLE outbox_events ADD CONSTRAINT outbox_canonical_envelope CHECK (
    (topic IS NULL AND is_processed) OR COALESCE((payload->>'schema_version' = '1' AND payload->>'event_id' = id::text
    AND payload->>'event_type' = event_type AND payload->>'aggregate_id' = aggregate_id
    AND payload ? 'occurred_at'
    AND ((topic = 'notification.commands.v1' AND event_type IN ('notification.email_verification','notification.password_reset')
          AND payload ? 'encrypted_payload' AND NOT payload ? 'payload')
      OR (topic = 'identity.events.v1' AND event_type LIKE 'identity.%'
          AND payload ? 'payload' AND NOT payload ? 'encrypted_payload'))
    ),false)
);
CREATE UNIQUE INDEX outbox_sequence ON outbox_events(sequence);
CREATE INDEX outbox_aggregate_pending ON outbox_events(aggregate_id,sequence) WHERE NOT is_processed;
CREATE INDEX outbox_claimable ON outbox_events(next_attempt_at,sequence) WHERE NOT is_processed;
