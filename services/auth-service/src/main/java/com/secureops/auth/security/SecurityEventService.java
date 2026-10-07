package com.secureops.auth.security;

import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class SecurityEventService {

    private final SecurityEventRepository securityEventRepository;

    public SecurityEventService(
            SecurityEventRepository securityEventRepository
    ) {
        this.securityEventRepository = securityEventRepository;
    }

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

        securityEventRepository.save(event);
    }
}