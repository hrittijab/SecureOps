package com.secureops.user.profile;

import com.secureops.user.security.AuthorizationEventService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@RestController
@RequestMapping("/api/users")
public class UserProfileController {

    private final UserProfileRepository repository;
    private final AuthorizationEventService eventService;

    public UserProfileController(
            UserProfileRepository repository,
            AuthorizationEventService eventService
    ) {
        this.repository = repository;
        this.eventService = eventService;
    }

    @GetMapping("/{profileId}")
    public UserProfile getProfile(
            @RequestHeader("X-User-Id") UUID authenticatedUserId,
            @PathVariable UUID profileId,
            HttpServletRequest request
    ) {
        UUID requestId = UUID.randomUUID();

        /*
         * Secure version:
         * enforce object-level authorization before
         * returning private profile data.
         */
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
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "Profile not found"
                ));

        eventService.record(
                authenticatedUserId,
                profileId,
                "AUTHORIZED",
                requestId,
                request.getRemoteAddr()
        );

        return profile;
    }
}