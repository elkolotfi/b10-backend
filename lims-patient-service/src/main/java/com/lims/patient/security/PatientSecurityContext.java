package com.lims.patient.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.UUID;

/**
 * Contexte de sécurité pour le service Patient.
 * Fournit des méthodes utilitaires pour accéder aux informations de l'utilisateur connecté.
 */
@Slf4j
@Component
public class PatientSecurityContext {

    /**
     * Récupère l'authentification courante
     */
    private Authentication getCurrentAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    /**
     * Récupère le JWT de l'utilisateur connecté
     */
    private Jwt getCurrentJwt() {
        Authentication auth = getCurrentAuthentication();
        if (auth instanceof JwtAuthenticationToken jwtAuth) {
            return jwtAuth.getToken();
        }
        return null;
    }

    /**
     * Récupère l'ID de l'utilisateur connecté
     */
    public String getCurrentUserId() {
        Jwt jwt = getCurrentJwt();
        return jwt != null ? jwt.getSubject() : null;
    }

    /**
     * Récupère l'email de l'utilisateur connecté
     */
    public String getCurrentUserEmail() {
        Jwt jwt = getCurrentJwt();
        return jwt != null ? jwt.getClaimAsString("email") : null;
    }

    /**
     * Récupère le type d'utilisateur connecté
     */
    public String getCurrentUserType() {
        Jwt jwt = getCurrentJwt();
        return jwt != null ? jwt.getClaimAsString("user_type") : null;
    }

    /**
     * Récupère le rôle de l'utilisateur connecté
     */
    public String getCurrentUserRole() {
        Jwt jwt = getCurrentJwt();
        return jwt != null ? jwt.getClaimAsString("role") : null;
    }

    /**
     * Récupère le realm de l'utilisateur connecté
     */
    public String getCurrentUserRealm() {
        Jwt jwt = getCurrentJwt();
        return jwt != null ? jwt.getClaimAsString("realm") : null;
    }

    /**
     * Récupère l'ID du laboratoire de l'utilisateur connecté (pour le staff)
     */
    public String getCurrentUserLaboratoryId() {
        Jwt jwt = getCurrentJwt();
        return jwt != null ? jwt.getClaimAsString("laboratory_id") : null;
    }

    /**
     * Récupère l'ID patient de l'utilisateur connecté (pour les patients)
     */
    public String getCurrentPatientId() {
        Jwt jwt = getCurrentJwt();
        return jwt != null ? jwt.getClaimAsString("patient_id") : null;
    }

    /**
     * Vérifie si l'utilisateur connecté est un admin
     */
    public boolean isCurrentUserAdmin() {
        String userType = getCurrentUserType();
        return "ADMIN".equals(userType);
    }

    /**
     * Vérifie si l'utilisateur connecté est un patient
     */
    public boolean isCurrentUserPatient() {
        String userType = getCurrentUserType();
        return "PATIENT".equals(userType);
    }

    /**
     * Vérifie si l'utilisateur connecté est un membre du staff
     */
    public boolean isCurrentUserStaff() {
        String userType = getCurrentUserType();
        return "STAFF".equals(userType);
    }

    /**
     * Vérifie si l'utilisateur a une autorité spécifique
     */
    private boolean hasAuthority(String authority) {
        Authentication auth = getCurrentAuthentication();
        if (auth != null) {
            Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
            return authorities.stream()
                    .anyMatch(a -> a.getAuthority().equals(authority));
        }
        return false;
    }

    /**
     * Vérifie si l'utilisateur peut accéder aux données d'un patient spécifique
     */
    public boolean canAccessPatient(UUID patientId) {
        log.debug("Checking access to patient {} for user {}", patientId, getCurrentUserId());

        // Les admins ont accès à tous les patients
        if (isCurrentUserAdmin()) {
            log.debug("Admin access granted to patient {}", patientId);
            return true;
        }

        // Les patients peuvent accéder à leurs propres données
        if (isCurrentUserPatient()) {
            String currentPatientId = getCurrentPatientId();
            boolean hasAccess = patientId.toString().equals(currentPatientId);
            log.debug("Patient access to patient {}: {}", patientId, hasAccess);
            return hasAccess;
        }

        // Le staff peut accéder aux patients de leur laboratoire
        if (isCurrentUserStaff()) {
            // Pour l'instant, on permet l'accès à tout le staff
            // Dans une implémentation complète, il faudrait vérifier si le patient
            // appartient au même laboratoire que le staff
            log.debug("Staff access granted to patient {} (basic implementation)", patientId);
            return true;
        }

        log.debug("Access denied to patient {} for user {}", patientId, getCurrentUserId());
        return false;
    }

    /**
     * Vérifie si l'utilisateur peut lire tous les patients
     */
    public boolean canReadAllPatients() {
        log.debug("Checking read all patients permission for user {}", getCurrentUserId());

        // Les admins peuvent lire tous les patients
        if (isCurrentUserAdmin()) {
            log.debug("Admin can read all patients");
            return true;
        }

        // Le staff peut lire les patients de leur laboratoire
        if (isCurrentUserStaff()) {
            log.debug("Staff can read patients in their laboratory");
            return true;
        }

        log.debug("Read all patients denied for user {}", getCurrentUserId());
        return false;
    }

    /**
     * Vérifie si l'utilisateur peut écrire/modifier des données patient
     */
    public boolean canWritePatient() {
        log.debug("Checking write patient permission for user {}", getCurrentUserId());

        // Les admins peuvent écrire
        if (isCurrentUserAdmin()) {
            log.debug("Admin can write patient data");
            return true;
        }

        // Le staff avec les bons rôles peut écrire
        if (isCurrentUserStaff()) {
            String role = getCurrentUserRole();
            boolean canWrite = "ADMIN_LAB".equals(role) || "SECRETAIRE".equals(role);
            log.debug("Staff write permission: {} (role: {})", canWrite, role);
            return canWrite;
        }

        log.debug("Write patient denied for user {}", getCurrentUserId());
        return false;
    }

    /**
     * Vérifie si l'utilisateur peut supprimer des patients
     */
    public boolean canDeletePatient() {
        log.debug("Checking delete patient permission for user {}", getCurrentUserId());

        // Seuls les admins peuvent supprimer
        boolean canDelete = isCurrentUserAdmin();
        log.debug("Delete patient permission: {} for user {}", canDelete, getCurrentUserId());
        return canDelete;
    }

    /**
     * Vérifie si l'utilisateur a une permission spécifique
     */
    public boolean hasPermission(String permission) {
        return hasAuthority("PERMISSION_" + permission);
    }

    /**
     * Vérifie si l'utilisateur a un rôle spécifique
     */
    public boolean hasRole(String role) {
        return hasAuthority("ROLE_" + role);
    }
}