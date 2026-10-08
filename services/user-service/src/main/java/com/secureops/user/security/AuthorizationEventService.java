package com.secureops.user.security;

import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class AuthorizationEventService {

    private final AuthorizationEventRepository repository;

    public AuthorizationEventService(
            AuthorizationEventRepository repository
    ) {
        this.repository = repository;
    }

    public void record(
            UUID actorUserId,
            UUID targetUserId,
            String outcome,
            UUID requestId,
            String sourceIp
    ) {
        repository.save(
                new AuthorizationEvent(
                        actorUserId,
                        targetUserId,
                        "READ_PROFILE",
                        outcome,
                        requestId,
                        sourceIp
                )
        );
    }
}