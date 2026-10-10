
package com.secureops.user.config;

import com.secureops.user.security.JwtAuthenticationEntryPoint;

import jakarta.servlet.DispatcherType;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import org.springframework.security.web.SecurityFilterChain;

import java.nio.file.Files;
import java.nio.file.Path;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import org.springframework.context.annotation.Profile;
import java.util.Base64;

@Configuration
public class SecurityConfig {

    @Bean
    @Profile("!lab")
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthenticationEntryPoint jwtEntryPoint
    ) throws Exception {

        http
            .csrf(csrf -> csrf.disable())

            .sessionManagement(session -> session
                .sessionCreationPolicy(
                    SessionCreationPolicy.STATELESS
                )
            )

            .authorizeHttpRequests(auth -> auth

                // Preserve original HTTP errors such as 404
                .dispatcherTypeMatchers(
                    DispatcherType.ERROR
                ).permitAll()

                // Public health endpoint
                .requestMatchers(
                    "/actuator/health"
                ).permitAll()

                // Allow authenticated users to read profiles
                .requestMatchers(
                    HttpMethod.GET,
                    "/api/users/*"
                ).authenticated()

                // Allow authenticated users to update profiles
                .requestMatchers(
                    HttpMethod.PATCH,
                    "/api/users/*"
                ).authenticated()

                // Deny all other requests
                .anyRequest().denyAll()
            )

            // JWT authentication and rejection telemetry
            .oauth2ResourceServer(oauth -> oauth
                .authenticationEntryPoint(jwtEntryPoint)
                .jwt(jwt -> {})
            );

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder(
            @Value("${secureops.jwt.public-key}") String keyPath
    ) throws Exception {

        // Read RSA public key from PEM file
        String pem = Files.readString(Path.of(keyPath));

        String encoded = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");

        byte[] bytes = Base64.getDecoder().decode(encoded);

        RSAPublicKey publicKey =
            (RSAPublicKey) KeyFactory
                .getInstance("RSA")
                .generatePublic(
                    new X509EncodedKeySpec(bytes)
                );

        // Verify JWT signatures using RS256
        NimbusJwtDecoder decoder =
            NimbusJwtDecoder
                .withPublicKey(publicKey)
                .signatureAlgorithm(
                    SignatureAlgorithm.RS256
                )
                .build();

        // Validate issuer, expiration and timestamps
        OAuth2TokenValidator<Jwt> issuerValidator =
            JwtValidators.createDefaultWithIssuer(
                "secureops-auth"
            );

        // Validate intended audience
        OAuth2TokenValidator<Jwt> audienceValidator = jwt -> {

            if (jwt.getAudience().contains(
                    "secureops-user-service"
            )) {
                return OAuth2TokenValidatorResult.success();
            }

            return OAuth2TokenValidatorResult.failure(
                new OAuth2Error(
                    "invalid_token",
                    "Invalid token audience",
                    null
                )
            );
        };

        // Apply all JWT validators
        decoder.setJwtValidator(
            new DelegatingOAuth2TokenValidator<>(
                issuerValidator,
                audienceValidator
            )
        );

        return decoder;
    }
}
