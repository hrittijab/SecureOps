
package com.secureops.user.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final JwtSecurityEventRepository repository;

    private final BearerTokenAuthenticationEntryPoint delegate =
            new BearerTokenAuthenticationEntryPoint();

    public JwtAuthenticationEntryPoint(
            JwtSecurityEventRepository repository
    ) {
        this.repository = repository;
    }

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) throws IOException {

        String authorization = request.getHeader("Authorization");

        // Missing credentials are not automatically classified
        // as a malicious JWT rejection.
        if (authorization != null
                && authorization.regionMatches(
                    true, 0, "Bearer ", 0, 7
                )) {

            String failureReason = "INVALID_TOKEN";

            // Do not persist raw tokens or exception messages.
            // A later phase can introduce structured failure
            // categories without exposing sensitive information.
            try {
                repository.save(
                    new JwtSecurityEvent(
                        failureReason,
                        request.getRemoteAddr()
                    )
                );
            } catch (RuntimeException error) {
                // Telemetry failure must not grant access or
                // prevent the authentication failure response.
                System.err.println(
                    "JWT security telemetry persistence failed"
                );
            }
        }

        delegate.commence(request, response, exception);
    }
}
