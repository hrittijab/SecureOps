
CREATE TABLE jwt_security_events (
    id UUID PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    failure_reason VARCHAR(50) NOT NULL,
    source_ip VARCHAR(45),
    request_id UUID NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_jwt_security_events_ip_time
ON jwt_security_events (source_ip, occurred_at);
