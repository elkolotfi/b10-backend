package com.lims.patient.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

/**
 * Utilitaire pour accéder au contexte de sécurité du service Patient
 *
 * Fournit des méthodes pour :
 * - Extraire l'ID du patient connecté
 * - Vérifier les permissions d'accès aux données
 * - Valider l'appartenance des données à l'utilisateur connecté
 */
@Component
@Slf4j
public class PatientSecurityContext {

    /**
     * Récupère l'ID du patient actuellement connecté
     * @return ID du patient ou null si pas connecté
     */
    public String getCurrentPatientId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return null;
        }

        // Si c'est un JWT, extraire le subject (patient ID)
        if (auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }

        return auth.getName();
    }

    /**
     * Récupère l'ID du staff actuellement connecté
     * @return ID du staff ou null si pas connecté ou pas staff
     */
    public String getCurrentStaffId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return null;
        }

        // Vérifier que c'est bien un staff
        if (!hasRole("STAFF") && !hasRole("ADMIN") && !hasRole("SECRETAIRE")) {
            return null;
        }

        if (auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }

        return auth.getName();
    }

    /**
     * Vérifie si l'utilisateur connecté a un rôle spécifique
     */
    public boolean hasRole(String role) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return false;
        }

        String roleWithPrefix = role.startsWith("ROLE_") ? role : "ROLE_" + role;
        return auth.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals(roleWithPrefix));
    }

    /**
     * Vérifie si l'utilisateur connecté est un patient
     */
    public boolean isPatient() {
        return hasRole("PATIENT");
    }

    /**
     * Vérifie si l'utilisateur connecté est du staff
     */
    public boolean isStaff() {
        return hasRole("STAFF") || hasRole("ADMIN") || hasRole("SECRETAIRE") ||
                hasRole("PRELEVEUR") || hasRole("TECHNICIEN") || hasRole("RESPONSABLE_QUALITE");
    }

    /**
     * Vérifie si l'utilisateur connecté est admin
     */
    public boolean isAdmin() {
        return hasRole("ADMIN") || hasRole("SUPER_ADMIN");
    }

    /**
     * Vérifie si un patient peut accéder à ses propres données
     * @param patientId ID du patient dont on veut accéder aux données
     * @return true si l'accès est autorisé
     */
    public boolean canAccessPatientData(String patientId) {
        // Le staff peut accéder à toutes les données patient
        if (isStaff()) {
            log.debug("Staff user {} accessing patient data {}", getCurrentStaffId(), patientId);
            return true;
        }

        // Un patient ne peut accéder qu'à ses propres données
        if (isPatient()) {
            String currentPatientId = getCurrentPatientId();
            boolean canAccess = patientId.equals(currentPatientId);

            if (!canAccess) {
                log.warn("Patient {} attempted to access data of patient {}", currentPatientId, patientId);
            }

            return canAccess;
        }

        // Aucun autre type d'utilisateur ne peut accéder aux données patient
        return false;
    }

    /**
     * Récupère le JWT complet pour accéder à des claims spécifiques
     */
    public Jwt getCurrentJwt() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt;
        }
        return null;
    }

    /**
     * Récupère une claim spécifique du JWT
     */
    public String getJwtClaim(String claimName) {
        Jwt jwt = getCurrentJwt();
        return jwt != null ? jwt.getClaimAsString(claimName) : null;
    }

    /**
     * Récupère l'ID du laboratoire pour un staff
     */
    public String getCurrentLaboratoryId() {
        if (!isStaff()) {
            return null;
        }
        return getJwtClaim("laboratory_id");
    }

    /**
     * Récupère le type d'utilisateur depuis le JWT
     */
    public String getUserType() {
        return getJwtClaim("user_type");
    }

    /**
     * Récupère le realm depuis le JWT
     */
    public String getRealm() {
        return getJwtClaim("realm");
    }

    /**
     * Récupère l'email de l'utilisateur connecté
     */
    public String getCurrentUserEmail() {
        return getJwtClaim("email");
    }

    /**
     * Vérifie si l'utilisateur connecté a vérifié son MFA (pour staff/admin)
     */
    public boolean isMfaVerified() {
        Jwt jwt = getCurrentJwt();
        if (jwt == null) {
            return false;
        }

        Boolean mfaVerified = jwt.getClaimAsBoolean("mfa_verified");
        return Boolean.TRUE.equals(mfaVerified);
    }

    /**
     * Récupère l'ID de session pour l'audit
     */
    public String getSessionId() {
        return getJwtClaim("session_id");
    }

    /**
     * Récupère des informations complètes sur l'utilisateur connecté
     */
    public UserInfo getCurrentUserInfo() {
        Jwt jwt = getCurrentJwt();
        if (jwt == null) {
            return null;
        }

        return UserInfo.builder()
                .userId(jwt.getSubject())
                .email(getJwtClaim("email"))
                .userType(getUserType())
                .realm(getRealm())
                .laboratoryId(getCurrentLaboratoryId())
                .sessionId(getSessionId())
                .isPatient(isPatient())
                .isStaff(isStaff())
                .isAdmin(isAdmin())
                .mfaVerified(isMfaVerified())
                .build();
    }

    /**
     * Classe pour encapsuler les informations utilisateur
     */
    @lombok.Data
    @lombok.Builder
    public static class UserInfo {
        private String userId;
        private String email;
        private String userType;
        private String realm;
        private String laboratoryId;
        private String sessionId;
        private boolean isPatient;
        private boolean isStaff;
        private boolean isAdmin;
        private boolean mfaVerified;
    }
}