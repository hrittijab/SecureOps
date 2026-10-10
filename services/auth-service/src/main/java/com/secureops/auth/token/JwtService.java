package com.secureops.auth.token;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
public class JwtService {

    private final JwtEncoder encoder;

    public JwtService(
            RSAPrivateKey privateKey,
            RSAPublicKey publicKey
    ) {
        RSAKey key = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .build();

        this.encoder = new NimbusJwtEncoder(
                new ImmutableJWKSet<>(new JWKSet(key))
        );
    }

    public String issueToken(UUID userId, String role) {
        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("secureops-auth")
                .subject(userId.toString())
                .audience(java.util.List.of("secureops-user-service"))
                .issuedAt(now)
                .expiresAt(now.plus(15, ChronoUnit.MINUTES))
                .claim("role", role)
                .build();

        JwsHeader header =
                JwsHeader.with(SignatureAlgorithm.RS256).build();

        return encoder.encode(
                JwtEncoderParameters.from(header, claims)
        ).getTokenValue();
    }
}