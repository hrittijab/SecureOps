package com.secureops.user.security;

import jakarta.persistence.*;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "authorization_events")
public class AuthorizationEvent {

    @Id
    private UUID id;

    @Column(name = "actor_user_id", nullable = false)
    private UUID actorUserId;

    @Column(name = "target_user_id", nullable = false)
    private UUID targetUserId;

    @Column(nullable = false)
    private String action;

    @Column(nullable = false)
    private String outcome;

    @Column(name = "request_id", nullable = false)
    private UUID requestId;

    @Column(name = "source_ip")
    private String sourceIp;

    @Column(name = "occurred_at", nullable = false)
    private OffsetDateTime occurredAt;

    protected AuthorizationEvent() {
    }

    public AuthorizationEvent(
            UUID actorUserId,
            UUID targetUserId,
            String action,
            String outcome,
            UUID requestId,
            String sourceIp
    ) {
        this.id = UUID.randomUUID();
        this.actorUserId = actorUserId;
        this.targetUserId = targetUserId;
        this.action = action;
        this.outcome = outcome;
        this.requestId = requestId;
        this.sourceIp = sourceIp;
        this.occurredAt = OffsetDateTime.now();
    }
}