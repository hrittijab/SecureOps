
package com.secureops.user.profile;

public record UpdateProfileRequest(
        String fullName,
        String phone,
        String address
) {
}
