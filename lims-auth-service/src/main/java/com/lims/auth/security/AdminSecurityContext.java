package com.lims.auth.security;

import lombok.Data;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * Contexte de sécurité pour les administrateurs LIMS
 * Fournit des méthodes utilitaires pour accéder aux informations de l'administrateur connecté
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AdminSecurityContext {

    private String adminId;
    private String email;
    private String firstName;
    private String lastName;
    private String role;
    private String realm;
    private String userType;
    private List<String> permissions;
    private String sessionId;
    private boolean mfaVerified;
    private LocalDateTime tokenIssuedAt;
    private LocalDateTime tokenExpiresAt;

    /**
     * Récupère le contexte de sécurité de l'administrateur actuellement connecté
     */
    public static AdminSecurityContext getCurrentContext() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }

        if (authentication.getPrincipal() instanceof Jwt jwt) {
            return fromJwt(jwt);
        }

        return null;
    }

    /**
     * Crée un contexte de sécurité à partir d'un JWT
     */
    public static AdminSecurityContext fromJwt(Jwt jwt) {
        return AdminSecurityContext.builder()
                .adminId(jwt.getSubject())
                .email(jwt.getClaimAsString("email"))
                .firstName(jwt.getClaimAsString("first_name"))
                .lastName(jwt.getClaimAsString("last_name"))
                .role(jwt.getClaimAsString("role"))
                .realm(jwt.getClaimAsString("realm"))
                .userType(jwt.getClaimAsString("user_type"))
                .permissions(jwt.getClaimAsStringList("permissions"))
                .sessionId(jwt.getClaimAsString("session_id"))
                .mfaVerified(jwt.getClaimAsBoolean("mfa_verified"))
                .tokenIssuedAt(jwt.getIssuedAt() != null ?
                        LocalDateTime.ofInstant(jwt.getIssuedAt(), java.time.ZoneId.systemDefault()) : null)
                .tokenExpiresAt(jwt.getExpiresAt() != null ?
                        LocalDateTime.ofInstant(jwt.getExpiresAt(), java.time.ZoneId.systemDefault()) : null)
                .build();
    }

    /**
     * Vérifie si l'administrateur a une permission spécifique
     */
    public boolean hasPermission(String permission) {
        return permissions != null && permissions.contains(permission);
    }

    /**
     * Vérifie si l'administrateur a l'un des rôles spécifiés
     */
    public boolean hasRole(String... roles) {
        if (role == null) return false;

        for (String r : roles) {
            if (role.equalsIgnoreCase(r)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Vérifie si l'administrateur est un super administrateur
     */
    public boolean isSuperAdmin() {
        return hasRole("SUPER_ADMIN");
    }

    /**
     * Vérifie si l'administrateur est un administrateur système
     */
    public boolean isSystemAdmin() {
        return hasRole("SYSTEM_ADMIN", "SUPER_ADMIN");
    }

    /**
     * Vérifie si l'administrateur peut gérer les utilisateurs
     */
    public boolean canManageUsers() {
        return hasPermission("USER_MANAGEMENT") || isSuperAdmin();
    }

    /**
     * Vérifie si l'administrateur peut lire les audits
     */
    public boolean canReadAudits() {
        return hasPermission("AUDIT_READ") || isSuperAdmin();
    }

    /**
     * Vérifie si l'administrateur peut modifier la configuration
     */
    public boolean canWriteConfiguration() {
        return hasPermission("CONFIGURATION_WRITE") || isSuperAdmin();
    }

    /**
     * Récupère le nom complet de l'administrateur
     */
    public String getFullName() {
        if (firstName != null && lastName != null) {
            return firstName + " " + lastName;
        } else if (firstName != null) {
            return firstName;
        } else if (lastName != null) {
            return lastName;
        } else {
            return email;
        }
    }

    /**
     * Vérifie si le token est encore valide
     */
    public boolean isTokenValid() {
        return tokenExpiresAt != null && tokenExpiresAt.isAfter(LocalDateTime.now());
    }

    /**
     * Vérifie si le MFA est vérifié
     */
    public boolean isMfaVerified() {
        return mfaVerified;
    }

    /**
     * Vérifie si l'administrateur appartient au bon realm
     */
    public boolean isValidRealm() {
        return "lims-admin".equals(realm);
    }

    /**
     * Vérifie si l'administrateur est du bon type
     */
    public boolean isValidUserType() {
        return "ADMIN".equals(userType);
    }

    /**
     * Validation complète du contexte de sécurité
     */
    public boolean isValid() {
        return adminId != null &&
                email != null &&
                isValidRealm() &&
                isValidUserType() &&
                isMfaVerified() &&
                isTokenValid();
    }

    /**
     * Méthodes utilitaires statiques
     */
    public static String getCurrentAdminId() {
        AdminSecurityContext context = getCurrentContext();
        return context != null ? context.getAdminId() : null;
    }

    public static String getCurrentAdminEmail() {
        AdminSecurityContext context = getCurrentContext();
        return context != null ? context.getEmail() : null;
    }

    public static String getCurrentSessionId() {
        AdminSecurityContext context = getCurrentContext();
        return context != null ? context.getSessionId() : null;
    }

    public static List<String> getCurrentPermissions() {
        AdminSecurityContext context = getCurrentContext();
        return context != null ? context.getPermissions() : List.of();
    }

    public static boolean currentUserHasPermission(String permission) {
        AdminSecurityContext context = getCurrentContext();
        return context != null && context.hasPermission(permission);
    }

    public static boolean currentUserHasRole(String... roles) {
        AdminSecurityContext context = getCurrentContext();
        return context != null && context.hasRole(roles);
    }
}