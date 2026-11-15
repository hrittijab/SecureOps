package com.secureops.auth.security;

import jakarta.persistence.*;
import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "security_event_outbox")
public class SecurityEventOutbox {

    @Id
    private UUID id;

    @Column(name = "event_id", nullable = false, unique = true)
    private UUID eventId;

    @Column(nullable = false)
    private String topic;

    @Column(name = "event_key", nullable = false)
    private String eventKey;

    @Column(nullable = false, columnDefinition = "text")
    private String payload;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    protected SecurityEventOutbox() {}

    public SecurityEventOutbox(
            UUID eventId,
            String topic,
            String eventKey,
            String payload
    ) {
        this.id = UUID.randomUUID();
        this.eventId = eventId;
        this.topic = topic;
        this.eventKey = eventKey;
        this.payload = payload;
        this.createdAt = OffsetDateTime.now();
    }
}
