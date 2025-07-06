package com.lims.patient.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Convertisseur JWT pour le service Patient
 *
 * Gère les tokens JWT provenant de deux realms :
 * - lims-patient : Pour les patients (accès lecture seule à leurs données)
 * - lims-staff : Pour le staff médical (accès complet CRUD)
 *
 * Similaire à AdminJwtAuthenticationConverter du service auth
 */
@Component
@Slf4j
public class PatientJwtAuthenticationConverter extends JwtAuthenticationConverter {

    private final JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    public PatientJwtAuthenticationConverter() {
        // Configurer le converter pour extraire les authorities customisées
        this.setJwtGrantedAuthoritiesConverter(this::extractAuthorities);
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        try {
            // Extraire le realm du token via l'issuer
            String issuer = jwt.getIssuer() != null ? jwt.getIssuer().toString() : "";
            String realm = extractRealmFromIssuer(issuer);

            log.debug("Processing JWT from realm: {} for subject: {}", realm, jwt.getSubject());

            // Traitement selon le realm
            return switch (realm) {
                case "lims-patient" -> extractPatientAuthorities(jwt);
                case "lims-staff" -> extractStaffAuthorities(jwt);
                case "lims-admin" -> extractAdminAuthorities(jwt); // Support pour les admins système
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
     * Extrait le nom du realm depuis l'issuer URI
     * Format attendu: http://localhost:8080/realms/lims-patient
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

    /**
     * Extrait les autorités pour un token patient (realm lims-patient)
     */
    private Collection<GrantedAuthority> extractPatientAuthorities(Jwt jwt) {
        // Vérifier le type d'utilisateur
        String userType = jwt.getClaimAsString("user_type");
        if (!"PATIENT".equals(userType)) {
            log.warn("Invalid user_type for patient realm: {}", userType);
            return Collections.emptyList();
        }

        // Les patients ont uniquement le rôle PATIENT
        log.debug("Granting PATIENT role for user: {}", jwt.getSubject());
        return List.of(new SimpleGrantedAuthority("ROLE_PATIENT"));
    }

    /**
     * Extrait les autorités pour un token staff (realm lims-staff)
     */
    private Collection<GrantedAuthority> extractStaffAuthorities(Jwt jwt) {
        // Vérifier le type d'utilisateur
        String userType = jwt.getClaimAsString("user_type");
        if (!"STAFF".equals(userType)) {
            log.warn("Invalid user_type for staff realm: {}", userType);
            return Collections.emptyList();
        }

        // Extraire les authorities par défaut
        Collection<GrantedAuthority> authorities = defaultGrantedAuthoritiesConverter.convert(jwt);

        // Ajouter les rôles spécifiques du realm staff
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
        if (realmAccess != null) {
            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) realmAccess.get("roles");
            if (roles != null) {
                Collection<GrantedAuthority> realmAuthorities = roles.stream()
                        .filter(this::isValidStaffRole)
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toList());

                // Combiner les authorities
                Collection<GrantedAuthority> combinedAuthorities = Stream.concat(authorities.stream(), realmAuthorities.stream())
                        .collect(Collectors.toList());

                log.debug("Granted authorities for staff user {}: {}", jwt.getSubject(), combinedAuthorities);
                return combinedAuthorities;
            }
        }

        log.warn("No realm_access found in staff JWT for user: {}", jwt.getSubject());
        return authorities;
    }

    /**
     * Extrait les autorités pour un token admin (realm lims-admin)
     * Permet aux admins système d'accéder aux données patient
     */
    private Collection<GrantedAuthority> extractAdminAuthorities(Jwt jwt) {
        // Vérifier le type d'utilisateur
        String userType = jwt.getClaimAsString("user_type");
        if (!"ADMIN".equals(userType)) {
            log.warn("Invalid user_type for admin realm: {}", userType);
            return Collections.emptyList();
        }

        // Extraire les authorities par défaut
        Collection<GrantedAuthority> authorities = defaultGrantedAuthoritiesConverter.convert(jwt);

        // Ajouter les rôles spécifiques du realm admin
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
        if (realmAccess != null) {
            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) realmAccess.get("roles");
            if (roles != null) {
                Collection<GrantedAuthority> realmAuthorities = roles.stream()
                        .filter(this::isValidAdminRole)
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toList());

                // Combiner les authorities
                Collection<GrantedAuthority> combinedAuthorities = Stream.concat(authorities.stream(), realmAuthorities.stream())
                        .collect(Collectors.toList());

                log.debug("Granted authorities for admin user {}: {}", jwt.getSubject(), combinedAuthorities);
                return combinedAuthorities;
            }
        }

        return authorities;
    }

    /**
     * Valide si le rôle est autorisé pour le staff
     */
    private boolean isValidStaffRole(String role) {
        return List.of("ADMIN", "SECRETAIRE", "PRELEVEUR", "TECHNICIEN", "RESPONSABLE_QUALITE", "STAFF")
                .contains(role);
    }

    /**
     * Valide si le rôle est autorisé pour les admins
     */
    private boolean isValidAdminRole(String role) {
        return List.of("SUPER_ADMIN", "SYSTEM_ADMIN", "SECURITY_ADMIN", "SUPPORT_ADMIN", "ADMIN")
                .contains(role);
    }
}