
package com.secureops.user.security;

import jakarta.persistence.*;
import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "jwt_security_events")
public class JwtSecurityEvent {

    @Id
    private UUID id;

    @Column(name = "event_type", nullable = false)
    private String eventType;

    @Column(name = "failure_reason", nullable = false)
    private String failureReason;

    @Column(name = "source_ip")
    private String sourceIp;

    @Column(name = "request_id", nullable = false)
    private UUID requestId;

    @Column(name = "occurred_at", nullable = false)
    private OffsetDateTime occurredAt;

    protected JwtSecurityEvent() {
    }

    public JwtSecurityEvent(
            String failureReason,
            String sourceIp
    ) {
        this.id = UUID.randomUUID();
        this.eventType = "JWT_REJECTED";
        this.failureReason = failureReason;
        this.sourceIp = sourceIp;
        this.requestId = UUID.randomUUID();
        this.occurredAt = OffsetDateTime.now();
    }
}
