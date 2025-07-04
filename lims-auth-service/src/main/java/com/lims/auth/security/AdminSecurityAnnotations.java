package com.lims.auth.security;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.*;

/**
 * Annotations de sécurité personnalisées pour les administrateurs LIMS
 */
public class AdminSecurityAnnotations {

    /**
     * Nécessite les permissions de super administrateur
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public @interface RequireSuperAdmin {
    }

    /**
     * Nécessite les permissions d'administrateur système
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasRole('SYSTEM_ADMIN') or hasRole('SUPER_ADMIN')")
    public @interface RequireSystemAdmin {
    }

    /**
     * Nécessite les permissions de gestion des utilisateurs
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasAuthority('USER_MANAGEMENT') or hasRole('SUPER_ADMIN')")
    public @interface RequireUserManagement {
    }

    /**
     * Nécessite les permissions de lecture des audits
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasAuthority('AUDIT_READ') or hasRole('SUPER_ADMIN')")
    public @interface RequireAuditRead {
    }

    /**
     * Nécessite les permissions de modification de la configuration
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasAuthority('CONFIGURATION_WRITE') or hasRole('SUPER_ADMIN')")
    public @interface RequireConfigurationWrite {
    }

    /**
     * Nécessite que le MFA soit vérifié
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("@adminSecurityContext.getCurrentContext() != null and @adminSecurityContext.getCurrentContext().isMfaVerified()")
    public @interface RequireMfaVerified {
    }

    /**
     * Nécessite une permission spécifique
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasAuthority(#permission) or hasRole('SUPER_ADMIN')")
    public @interface RequirePermission {
        String value();
    }

    /**
     * Nécessite un rôle spécifique
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasRole(#role)")
    public @interface RequireRole {
        String value();
    }

    /**
     * Nécessite que l'utilisateur soit authentifié et du bon realm
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("isAuthenticated() and @adminSecurityContext.getCurrentContext() != null and @adminSecurityContext.getCurrentContext().isValidRealm()")
    public @interface RequireAdminRealm {
    }
}