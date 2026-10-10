package com.secureops.user.profile;

import jakarta.persistence.*;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "user_profiles")
public class UserProfile {

    @Id
    private UUID id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(name = "full_name", nullable = false)
    private String fullName;

    private String phone;

    private String address;

    @Column(name = "account_tier", nullable = false)
    private String accountTier;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    protected UserProfile() {
    }

    public UUID getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getFullName() {
        return fullName;
    }

    public String getPhone() {
        return phone;
    }

    public String getAddress() {
        return address;
    }

    public String getAccountTier() {
        return accountTier;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }
    public void updateContactDetails(
        String fullName,
        String phone,
        String address
    ) {
        this.fullName = fullName;
        this.phone = phone;
        this.address = address;
    }

    public void labUpdateAccountTier(String accountTier) {
        this.accountTier = accountTier;
    }
}