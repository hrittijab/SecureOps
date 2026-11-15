CREATE TABLE security_event_outbox (
    id UUID PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE
        REFERENCES security_events(id),
    topic VARCHAR(255) NOT NULL,
    event_key VARCHAR(255) NOT NULL,
    payload TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
);

CREATE INDEX idx_security_event_outbox_pending
    ON security_event_outbox (created_at)
    WHERE published_at IS NULL;
