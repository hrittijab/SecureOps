package com.secureops.user.security;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface AuthorizationEventRepository
        extends JpaRepository<AuthorizationEvent, UUID> {
}