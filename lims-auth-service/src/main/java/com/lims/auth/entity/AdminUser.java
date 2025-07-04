// AdminUser.java
package com.lims.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "admin_users", schema = "lims_auth")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AdminUser {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", columnDefinition = "uuid")
    private String id;

    @Column(name = "email", nullable = false, unique = true)
    private String email;

    @Column(name = "first_name", nullable = false)
    private String firstName;

    @Column(name = "last_name", nullable = false)
    private String lastName;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private AdminRole role;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "admin_user_permissions", schema = "lims_auth",
            joinColumns = @JoinColumn(name = "admin_user_id"))
    @Column(name = "permission")
    private List<String> permissions;

    @Column(name = "enabled", nullable = false)
    @Builder.Default
    private Boolean enabled = true;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    @Builder.Default
    private AdminStatus status = AdminStatus.ACTIVE;

    @Column(name = "mfa_enabled", nullable = false)
    @Builder.Default
    private Boolean mfaEnabled = false;

    @Column(name = "mfa_setup_at")
    private LocalDateTime mfaSetupAt;

    @Column(name = "failed_attempts", nullable = false)
    @Builder.Default
    private Integer failedAttempts = 0;

    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    @Column(name = "last_login_ip")
    private String lastLoginIp;

    @Column(name = "created_by")
    private String createdBy;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "keycloak_id")
    private String keycloakId;

    // Méthodes utilitaires
    public boolean isEnabled() {
        return enabled != null && enabled;
    }

    public boolean isMfaEnabled() {
        return mfaEnabled != null && mfaEnabled;
    }

    public boolean isTemporarilyLocked() {
        return lockedUntil != null && lockedUntil.isAfter(LocalDateTime.now());
    }

    public String getFullName() {
        return firstName + " " + lastName;
    }

    public enum AdminRole {
        SUPER_ADMIN("Super Administrateur"),
        SYSTEM_ADMIN("Administrateur Système"),
        USER_ADMIN("Administrateur Utilisateurs"),
        AUDIT_ADMIN("Administrateur Audit");

        private final String displayName;

        AdminRole(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    public enum AdminStatus {
        ACTIVE("Actif"),
        INACTIVE("Inactif"),
        SUSPENDED("Suspendu"),
        LOCKED("Verrouillé");

        private final String displayName;

        AdminStatus(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }
}