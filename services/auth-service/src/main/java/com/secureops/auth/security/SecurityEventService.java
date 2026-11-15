package com.secureops.auth.security;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class SecurityEventService {

    private static final String TOPIC =
            "secureops.security-events.v1";

    private final SecurityEventRepository securityEventRepository;
    private final SecurityEventOutboxRepository outboxRepository;
    private final ObjectMapper objectMapper;

    public SecurityEventService(
            SecurityEventRepository securityEventRepository,
            SecurityEventOutboxRepository outboxRepository,
            ObjectMapper objectMapper
    ) {
        this.securityEventRepository = securityEventRepository;
        this.outboxRepository = outboxRepository;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public void record(
            String eventType,
            UUID userId,
            String email,
            String sourceIp,
            UUID requestId,
            String outcome,
            String failureReason
    ) {
        SecurityEvent event = new SecurityEvent(
                eventType,
                userId,
                email,
                sourceIp,
                requestId,
                outcome,
                failureReason
        );

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("event_id", event.getId().toString());
        payload.put("service", "auth-service");
        payload.put("event_type", event.getEventType());
        payload.put("actor", event.getEmail());
        payload.put("target", event.getEmail());
        payload.put("source_ip", event.getSourceIp());
        payload.put("outcome", event.getOutcome());
        payload.put("timestamp", event.getOccurredAt().toString());

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("user_id", event.getUserId());
        metadata.put("request_id", event.getRequestId());
        metadata.put("failure_reason", event.getFailureReason());
        payload.put("metadata", metadata);

        final String json;
        try {
            json = objectMapper.writeValueAsString(payload);
        } catch (JacksonException exception) {
            throw new IllegalStateException(
                    "Failed to serialize security event",
                    exception
            );
        }

        securityEventRepository.save(event);

        outboxRepository.save(
                new SecurityEventOutbox(
                        event.getId(),
                        TOPIC,
                        event.getId().toString(),
                        json
                )
        );
    }
}
