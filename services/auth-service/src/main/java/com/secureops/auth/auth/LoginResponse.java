package com.secureops.auth.auth;

import java.util.UUID;

public record LoginResponse(
        UUID userId,
        String email,
        String role,
        String message,
        String accessToken,
        String tokenType,
        long expiresIn
) {
}