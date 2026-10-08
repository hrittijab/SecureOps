CREATE TABLE authorization_events (
    id UUID PRIMARY KEY,
    actor_user_id UUID NOT NULL,
    target_user_id UUID NOT NULL,
    action VARCHAR(100) NOT NULL,
    outcome VARCHAR(30) NOT NULL,
    request_id UUID NOT NULL,
    source_ip VARCHAR(45),
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_authorization_actor
    ON authorization_events(actor_user_id);

CREATE INDEX idx_authorization_target
    ON authorization_events(target_user_id);

CREATE INDEX idx_authorization_occurred_at
    ON authorization_events(occurred_at);