ALTER TABLE security_event_outbox
    ADD COLUMN claim_token UUID,
    ADD COLUMN claimed_until TIMESTAMPTZ,
    ADD COLUMN next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX idx_security_event_outbox_ready
    ON security_event_outbox (next_attempt_at, created_at)
    WHERE published_at IS NULL;

CREATE INDEX idx_security_event_outbox_claim_expiry
    ON security_event_outbox (claimed_until)
    WHERE published_at IS NULL
      AND claim_token IS NOT NULL;
