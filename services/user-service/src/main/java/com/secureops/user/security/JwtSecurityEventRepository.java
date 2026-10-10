
package com.secureops.user.security;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.UUID;

public interface JwtSecurityEventRepository
        extends JpaRepository<JwtSecurityEvent, UUID> {
}
