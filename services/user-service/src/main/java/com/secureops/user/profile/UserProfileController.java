
package com.secureops.user.profile;

import com.secureops.user.security.AuthorizationEventService;
import com.secureops.user.security.MassAssignmentEventService;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@RestController
@RequestMapping("/api/users")
public class UserProfileController {

    private static final Set<String> ALLOWED_FIELDS =
            Set.of("fullName", "phone", "address");

    private final UserProfileRepository repository;
    private final AuthorizationEventService eventService;
    private final MassAssignmentEventService massAssignmentEventService;

    public UserProfileController(
            UserProfileRepository repository,
            AuthorizationEventService eventService,
            MassAssignmentEventService massAssignmentEventService
    ) {
        this.repository = repository;
        this.eventService = eventService;
        this.massAssignmentEventService = massAssignmentEventService;
    }

    @GetMapping("/{profileId}")
    public UserProfile getProfile(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID profileId,
            HttpServletRequest request
    ) {
        UUID requestId = UUID.randomUUID();

        UUID authenticatedUserId = getAuthenticatedUserId(jwt);

        if (!authenticatedUserId.equals(profileId)) {

            eventService.record(
                    authenticatedUserId,
                    profileId,
                    "DENIED",
                    requestId,
                    request.getRemoteAddr()
            );

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

        eventService.record(
                authenticatedUserId,
                profileId,
                "AUTHORIZED",
                requestId,
                request.getRemoteAddr()
        );

        return profile;
    }

    @PatchMapping("/{profileId}")
    @Transactional
    public UserProfile updateProfile(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID profileId,
            @RequestBody Map<String, Object> payload,
            HttpServletRequest request
    ) {
        UUID authenticatedUserId = getAuthenticatedUserId(jwt);

        // Prevent cross-user profile modifications.
        if (!authenticatedUserId.equals(profileId)) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "Access denied"
            );
        }

        // Identify fields that the client is not allowed to update.
        Set<String> rejectedFields = new HashSet<>(
                payload.keySet()
        );

        rejectedFields.removeAll(ALLOWED_FIELDS);

        if (!rejectedFields.isEmpty()) {

            // Persist the blocked attack as a security event.
            massAssignmentEventService.recordBlocked(
                    authenticatedUserId,
                    profileId,
                    rejectedFields,
                    request.getRemoteAddr()
            );

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Request contains fields that cannot be updated"
            );
        }

        // Validate allowed field types and lengths.
        for (Map.Entry<String, Object> entry : payload.entrySet()) {

            String field = entry.getKey();
            Object value = entry.getValue();

            if (value != null && !(value instanceof String)) {
                throw new ResponseStatusException(
                        HttpStatus.BAD_REQUEST,
                        "Profile fields must be strings"
                );
            }

            if ("fullName".equals(field) && value == null) {
                throw new ResponseStatusException(
                        HttpStatus.BAD_REQUEST,
                        "Full name cannot be null"
                );
            }

            if (value instanceof String text) {

                int maxLength = switch (field) {
                    case "phone" -> 50;
                    case "address" -> 500;
                    default -> 255;
                };

                if (text.length() > maxLength) {
                    throw new ResponseStatusException(
                            HttpStatus.BAD_REQUEST,
                            field + " exceeds maximum length"
                    );
                }

                if ("fullName".equals(field)
                        && text.isBlank()) {
                    throw new ResponseStatusException(
                            HttpStatus.BAD_REQUEST,
                            "Full name cannot be blank"
                    );
                }
            }
        }

        UserProfile profile = repository.findById(profileId)
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.NOT_FOUND,
                                "Profile not found"
                        )
                );

        String fullName = payload.containsKey("fullName")
                ? (String) payload.get("fullName")
                : profile.getFullName();

        String phone = payload.containsKey("phone")
                ? (String) payload.get("phone")
                : profile.getPhone();

        String address = payload.containsKey("address")
                ? (String) payload.get("address")
                : profile.getAddress();

        profile.updateContactDetails(
                fullName,
                phone,
                address
        );

        return repository.save(profile);
    }

    private UUID getAuthenticatedUserId(Jwt jwt) {

        if (jwt == null || jwt.getSubject() == null) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Missing user identity"
            );
        }

        try {
            return UUID.fromString(jwt.getSubject());
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid user identity"
            );
        }
    }
}
