
package com.secureops.user.lab;

import com.secureops.user.security.JwtAuthenticationEntryPoint;

import jakarta.servlet.DispatcherType;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@Profile("lab")
public class LabSecurityConfig {

    @Bean
    public SecurityFilterChain labSecurityFilterChain(
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
                .dispatcherTypeMatchers(
                    DispatcherType.ERROR
                ).permitAll()

                .requestMatchers(
                    "/actuator/health"
                ).permitAll()

                .requestMatchers(
                    HttpMethod.GET,
                    "/api/users/*"
                ).authenticated()

                .requestMatchers(
                    HttpMethod.PATCH,
                    "/api/users/*"
                ).authenticated()

                .requestMatchers(
                    HttpMethod.PATCH,
                    "/api/lab/users/*/vulnerable"
                ).authenticated()

                .anyRequest().denyAll()
            )
            .oauth2ResourceServer(oauth -> oauth
                .authenticationEntryPoint(jwtEntryPoint)
                .jwt(jwt -> {})
            );

        return http.build();
    }
}
