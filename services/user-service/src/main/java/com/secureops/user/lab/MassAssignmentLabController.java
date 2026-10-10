
package com.secureops.user.lab;

import com.secureops.user.profile.UserProfile;
import com.secureops.user.profile.UserProfileRepository;

import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.UUID;

@RestController
@Profile("lab")
@RequestMapping("/api/lab/users")
public class MassAssignmentLabController {

    private final UserProfileRepository repository;

    public MassAssignmentLabController(
            UserProfileRepository repository
    ) {
        this.repository = repository;
    }

    @PatchMapping("/{profileId}/vulnerable")
    @Transactional
    public UserProfile vulnerableUpdate(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID profileId,
            @RequestBody Map<String, Object> payload
    ) {
        UUID authenticatedUserId;

        try {
            authenticatedUserId = UUID.fromString(jwt.getSubject());
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid user identity"
            );
        }

        if (!authenticatedUserId.equals(profileId)) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "Access denied"
            );
        }

        UserProfile profile = repository.findById(profileId)
                .orElseThrow(() ->
                    new ResponseStatusException(
                            HttpStatus.NOT_FOUND,
                            "Profile not found"
                    )
                );

        // INTENTIONALLY VULNERABLE:
        // A client can modify accountTier.
        Object accountTier = payload.get("accountTier");

        if (accountTier instanceof String tier) {
            profile.labUpdateAccountTier(tier);
        }

        return repository.save(profile);
    }
}
