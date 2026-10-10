
package com.secureops.user.security;

import jakarta.persistence.*;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "mass_assignment_events")
public class MassAssignmentEvent {

    @Id
    private UUID id;

    @Column(name = "actor_user_id", nullable = false)
    private UUID actorUserId;

    @Column(name = "target_user_id", nullable = false)
    private UUID targetUserId;

    @Column(name = "event_type", nullable = false)
    private String eventType;

    @Column(nullable = false)
    private String outcome;

    @Column(name = "attempted_fields", nullable = false)
    private String attemptedFields;

    @Column(name = "source_ip")
    private String sourceIp;

    @Column(name = "request_id", nullable = false)
    private UUID requestId;

    @Column(name = "occurred_at", nullable = false)
    private OffsetDateTime occurredAt;

    protected MassAssignmentEvent() {
    }

    public MassAssignmentEvent(
            UUID actorUserId,
            UUID targetUserId,
            String attemptedFields,
            String sourceIp
    ) {
        this.id = UUID.randomUUID();
        this.actorUserId = actorUserId;
        this.targetUserId = targetUserId;
        this.eventType = "MASS_ASSIGNMENT_ATTEMPT";
        this.outcome = "BLOCKED";
        this.attemptedFields = attemptedFields;
        this.sourceIp = sourceIp;
        this.requestId = UUID.randomUUID();
        this.occurredAt = OffsetDateTime.now();
    }
}
