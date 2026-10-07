CREATE TABLE security_events (
    id UUID PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    user_id UUID,
    email VARCHAR(255),
    source_ip VARCHAR(45),
    request_id UUID NOT NULL,
    outcome VARCHAR(20) NOT NULL,
    failure_reason VARCHAR(100),
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_security_events_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE SET NULL
);

CREATE INDEX idx_security_events_event_type
    ON security_events(event_type);

CREATE INDEX idx_security_events_email
    ON security_events(email);

CREATE INDEX idx_security_events_occurred_at
    ON security_events(occurred_at);

CREATE INDEX idx_security_events_source_ip
    ON security_events(source_ip);