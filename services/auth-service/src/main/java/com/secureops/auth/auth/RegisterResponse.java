package com.secureops.auth.auth;

import java.util.UUID;

public record RegisterResponse(
        UUID id,
        String email,
        String role
) {
}