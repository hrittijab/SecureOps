
package com.secureops.user.security;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.UUID;

@Service
public class MassAssignmentEventService {

    private final MassAssignmentEventRepository repository;

    public MassAssignmentEventService(
            MassAssignmentEventRepository repository
    ) {
        this.repository = repository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordBlocked(
            UUID actorUserId,
            UUID targetUserId,
            Set<String> rejectedFields,
            String sourceIp
    ) {
        repository.save(
                new MassAssignmentEvent(
                        actorUserId,
                        targetUserId,
                        String.join(",", new java.util.TreeSet<>(rejectedFields)),
                        sourceIp
                )
        );
    }
}
