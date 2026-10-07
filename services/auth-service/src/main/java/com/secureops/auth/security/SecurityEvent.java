package com.secureops.auth.security;

import jakarta.persistence.*;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "security_events")
public class SecurityEvent {

    @Id
    private UUID id;

    @Column(name = "event_type", nullable = false)
    private String eventType;

    @Column(name = "user_id")
    private UUID userId;

    private String email;

    @Column(name = "source_ip")
    private String sourceIp;

    @Column(name = "request_id", nullable = false)
    private UUID requestId;

    @Column(nullable = false)
    private String outcome;

    @Column(name = "failure_reason")
    private String failureReason;

    @Column(name = "occurred_at", nullable = false)
    private OffsetDateTime occurredAt;

    protected SecurityEvent() {
    }

    public SecurityEvent(
            String eventType,
            UUID userId,
            String email,
            String sourceIp,
            UUID requestId,
            String outcome,
            String failureReason
    ) {
        this.id = UUID.randomUUID();
        this.eventType = eventType;
        this.userId = userId;
        this.email = email;
        this.sourceIp = sourceIp;
        this.requestId = requestId;
        this.outcome = outcome;
        this.failureReason = failureReason;
        this.occurredAt = OffsetDateTime.now();
    }

    public UUID getId() {
        return id;
    }

    public String getEventType() {
        return eventType;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getEmail() {
        return email;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public UUID getRequestId() {
        return requestId;
    }

    public String getOutcome() {
        return outcome;
    }

    public String getFailureReason() {
        return failureReason;
    }

    public OffsetDateTime getOccurredAt() {
        return occurredAt;
    }
}