
CREATE TABLE mass_assignment_events (
    id UUID PRIMARY KEY,
    actor_user_id UUID NOT NULL,
    target_user_id UUID NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    outcome VARCHAR(50) NOT NULL,
    attempted_fields VARCHAR(500) NOT NULL,
    source_ip VARCHAR(45),
    request_id UUID NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_mass_assignment_events_actor_time
ON mass_assignment_events (
    actor_user_id,
    occurred_at
);
