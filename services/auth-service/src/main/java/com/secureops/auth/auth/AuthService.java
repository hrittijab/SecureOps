package com.secureops.auth.auth;

import com.secureops.auth.security.SecurityEventService;
import com.secureops.auth.user.User;
import com.secureops.auth.user.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.Locale;
import java.util.UUID;

@Service
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCK_MINUTES = 15;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecurityEventService securityEventService;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            SecurityEventService securityEventService
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.securityEventService = securityEventService;
    }

    @Transactional
    public RegisterResponse register(RegisterRequest request) {

        String normalizedEmail =
                request.email().trim().toLowerCase(Locale.ROOT);

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new IllegalArgumentException(
                    "Email is already registered"
            );
        }

        String passwordHash =
                passwordEncoder.encode(request.password());

        User user = new User(
                normalizedEmail,
                passwordHash
        );

        User savedUser = userRepository.save(user);

        return new RegisterResponse(
                savedUser.getId(),
                savedUser.getEmail(),
                savedUser.getRole()
        );
    }

    @Transactional(noRollbackFor = AuthenticationFailedException.class)
    public LoginResponse login(
            LoginRequest request,
            String sourceIp,
            UUID requestId
    ) {

        String normalizedEmail =
                request.email().trim().toLowerCase(Locale.ROOT);

        User user = userRepository.findByEmail(normalizedEmail)
                .orElse(null);

        // Unknown account
        if (user == null) {

            securityEventService.record(
                    "LOGIN_FAILURE",
                    null,
                    normalizedEmail,
                    sourceIp,
                    requestId,
                    "FAILURE",
                    "INVALID_CREDENTIALS"
            );

            throw new AuthenticationFailedException(
                    "Invalid email or password"
            );
        }

        // Disabled account
        if (!user.isEnabled()) {

            securityEventService.record(
                    "LOGIN_FAILURE",
                    user.getId(),
                    user.getEmail(),
                    sourceIp,
                    requestId,
                    "FAILURE",
                    "ACCOUNT_DISABLED"
            );

            throw new AuthenticationFailedException(
                    "Account is disabled"
            );
        }

        // Already locked account
        if (user.isLocked()) {

            securityEventService.record(
                    "LOGIN_FAILURE",
                    user.getId(),
                    user.getEmail(),
                    sourceIp,
                    requestId,
                    "FAILURE",
                    "ACCOUNT_LOCKED"
            );

            throw new AuthenticationFailedException(
                    "Account is temporarily locked"
            );
        }

        // Incorrect password
        if (!passwordEncoder.matches(
                request.password(),
                user.getPasswordHash()
        )) {

            user.recordFailedLogin();

            // Every incorrect password is a failed login,
            // including the attempt that causes account lockout.
            securityEventService.record(
                    "LOGIN_FAILURE",
                    user.getId(),
                    user.getEmail(),
                    sourceIp,
                    requestId,
                    "FAILURE",
                    "INVALID_CREDENTIALS"
            );

            // Lock account when threshold is reached.
            if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {

                user.lockUntil(
                        OffsetDateTime.now().plusMinutes(LOCK_MINUTES)
                );

                securityEventService.record(
                        "ACCOUNT_LOCKED",
                        user.getId(),
                        user.getEmail(),
                        sourceIp,
                        requestId,
                        "FAILURE",
                        "TOO_MANY_FAILED_ATTEMPTS"
                );
            }

            throw new AuthenticationFailedException(
                    "Invalid email or password"
            );
        }

        // Successful authentication resets previous failures.
        user.resetFailedLoginAttempts();

        securityEventService.record(
                "LOGIN_SUCCESS",
                user.getId(),
                user.getEmail(),
                sourceIp,
                requestId,
                "SUCCESS",
                null
        );

        return new LoginResponse(
                user.getId(),
                user.getEmail(),
                user.getRole(),
                "Login successful"
        );
    }
}