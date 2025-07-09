package com.lims.patient.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Convertisseur d'authentification JWT personnalisé pour le service Patient.
 *
 * Gère les tokens provenant de trois realms différents :
 * - lims-admin : Admins système (accès complet)
 * - lims-patient : Patients (accès à leurs propres données)
 * - lims-staff : Personnel laboratoire (accès selon laboratoire)
 */
@Slf4j
public class PatientJwtAuthenticationConverter extends JwtAuthenticationConverter {

    private final JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter;

    public PatientJwtAuthenticationConverter() {
        this.defaultGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        // Configurer le converter pour extraire les authorities customisées
        this.setJwtGrantedAuthoritiesConverter(this::extractAuthorities);
    }

    /**
     * Extrait les autorités depuis le JWT selon le realm d'origine
     */
    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        try {
            // Extraire les informations de base du JWT
            String realm = jwt.getClaimAsString("realm");
            String userType = jwt.getClaimAsString("user_type");
            String subject = jwt.getSubject();

            log.debug("Processing JWT from realm: {} for subject: {} with user_type: {}",
                    realm, subject, userType);

            // Traitement selon le realm
            return switch (realm) {
                case "lims-admin" -> extractAdminAuthorities(jwt);
                case "lims-patient" -> extractPatientAuthorities(jwt);
                case "lims-staff" -> extractStaffAuthorities(jwt);
                default -> {
                    log.warn("Unknown or unsupported realm in JWT: {}", realm);
                    yield Collections.emptyList();
                }
            };

        } catch (Exception e) {
            log.error("Error processing JWT authorities: {}", e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    /**
     * Extrait les autorités pour un token admin (realm lims-admin)
     */
    private Collection<GrantedAuthority> extractAdminAuthorities(Jwt jwt) {
        String userType = jwt.getClaimAsString("user_type");
        if (!"ADMIN".equals(userType)) {
            log.warn("Invalid user_type for admin realm: {}", userType);
            return Collections.emptyList();
        }

        List<GrantedAuthority> authorities = new ArrayList<>();

        // Ajouter le rôle de base ADMIN
        authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));

        // Extraire le rôle spécifique depuis le JWT
        String role = jwt.getClaimAsString("role");
        if (role != null) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            log.debug("Added admin role: ROLE_{}", role);
        }

        // Extraire les permissions spécifiques
        List<String> permissions = jwt.getClaimAsStringList("permissions");
        if (permissions != null) {
            for (String permission : permissions) {
                authorities.add(new SimpleGrantedAuthority("PERMISSION_" + permission));
                log.debug("Added admin permission: PERMISSION_{}", permission);
            }
        }

        // Extraire les rôles Keycloak du realm
        Collection<GrantedAuthority> realmAuthorities = extractKeycloakRealmRoles(jwt);
        authorities.addAll(realmAuthorities);

        log.debug("Admin authorities granted: {}", authorities.size());
        return authorities;
    }

    /**
     * Extrait les autorités pour un token patient (realm lims-patient)
     */
    private Collection<GrantedAuthority> extractPatientAuthorities(Jwt jwt) {
        String userType = jwt.getClaimAsString("user_type");
        if (!"PATIENT".equals(userType)) {
            log.warn("Invalid user_type for patient realm: {}", userType);
            return Collections.emptyList();
        }

        List<GrantedAuthority> authorities = new ArrayList<>();

        // Les patients ont uniquement le rôle PATIENT
        authorities.add(new SimpleGrantedAuthority("ROLE_PATIENT"));

        // Ajouter des permissions spécifiques aux patients
        authorities.add(new SimpleGrantedAuthority("PERMISSION_READ_OWN_DATA"));
        authorities.add(new SimpleGrantedAuthority("PERMISSION_UPDATE_OWN_CONTACT"));

        // Extraire les rôles Keycloak du realm
        Collection<GrantedAuthority> realmAuthorities = extractKeycloakRealmRoles(jwt);
        authorities.addAll(realmAuthorities);

        log.debug("Patient authorities granted for subject {}: {}", jwt.getSubject(), authorities.size());
        return authorities;
    }

    /**
     * Extrait les autorités pour un token staff (realm lims-staff)
     */
    private Collection<GrantedAuthority> extractStaffAuthorities(Jwt jwt) {
        String userType = jwt.getClaimAsString("user_type");
        if (!"STAFF".equals(userType)) {
            log.warn("Invalid user_type for staff realm: {}", userType);
            return Collections.emptyList();
        }

        List<GrantedAuthority> authorities = new ArrayList<>();

        // Ajouter le rôle de base STAFF
        authorities.add(new SimpleGrantedAuthority("ROLE_STAFF"));

        // Extraire le rôle spécifique du staff
        String role = jwt.getClaimAsString("role");
        if (role != null) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            log.debug("Added staff role: ROLE_{}", role);
        }

        // Ajouter des permissions spécifiques selon le rôle
        if (role != null) {
            switch (role) {
                case "ADMIN_LAB":
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_READ_ALL_PATIENTS_IN_LAB"));
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_WRITE_ALL_PATIENTS_IN_LAB"));
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_MANAGE_APPOINTMENTS"));
                    break;
                case "SECRETAIRE":
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_READ_PATIENTS_IN_LAB"));
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_SCHEDULE_APPOINTMENTS"));
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_UPDATE_PATIENT_CONTACT"));
                    break;
                case "PRELEVEUR", "TECHNICIEN":
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_READ_PATIENTS_IN_LAB"));
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_VIEW_APPOINTMENTS"));
                    break;
                default:
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_READ_PATIENTS_IN_LAB"));
            }
        }

        // Extraire les rôles Keycloak du realm
        Collection<GrantedAuthority> realmAuthorities = extractKeycloakRealmRoles(jwt);
        authorities.addAll(realmAuthorities);

        log.debug("Staff authorities granted for subject {}: {}", jwt.getSubject(), authorities.size());
        return authorities;
    }

    /**
     * Extrait les rôles Keycloak du realm depuis le token
     */
    private Collection<GrantedAuthority> extractKeycloakRealmRoles(Jwt jwt) {
        try {
            Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
            if (realmAccess != null) {
                @SuppressWarnings("unchecked")
                List<String> roles = (List<String>) realmAccess.get("roles");
                if (roles != null) {
                    return roles.stream()
                            .filter(role -> !role.startsWith("default-") && !role.equals("offline_access"))
                            .map(role -> new SimpleGrantedAuthority("KEYCLOAK_ROLE_" + role.toUpperCase()))
                            .collect(Collectors.toList());
                }
            }
        } catch (Exception e) {
            log.debug("Could not extract Keycloak realm roles: {}", e.getMessage());
        }
        return Collections.emptyList();
    }

    /**
     * Extrait le nom du realm depuis l'issuer URI
     * Format attendu: http://localhost:8080/realms/lims-admin
     */
    private String extractRealmFromIssuer(String issuer) {
        if (issuer == null || issuer.isEmpty()) {
            return "unknown";
        }

        if (issuer.contains("/realms/")) {
            String[] parts = issuer.split("/realms/");
            if (parts.length > 1) {
                return parts[1];
            }
        }

        return "unknown";
    }
}