package com.lims.patient.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Décodeur JWT personnalisé capable de gérer plusieurs realms Keycloak avec HMAC signing.
 *
 * Correction: Utilise SecretKeySpec pour HS512 au lieu de JWK Set URI qui est pour RSA.
 */
@Slf4j
public class MultiRealmJwtDecoder implements JwtDecoder {

    private final String keycloakBaseUrl;
    private final Map<String, JwtDecoder> realmDecoders;

    // Realms supportés
    private static final String LIMS_ADMIN_REALM = "lims-admin";
    private static final String LIMS_PATIENT_REALM = "lims-patient";
    private static final String LIMS_STAFF_REALM = "lims-staff";

    // Clés secrètes pour chaque realm
    private final String adminSecret;
    private final String patientSecret;
    private final String staffSecret;

    public MultiRealmJwtDecoder(String keycloakBaseUrl, String adminSecret, String patientSecret, String staffSecret) {
        this.keycloakBaseUrl = keycloakBaseUrl;
        this.adminSecret = adminSecret;
        this.patientSecret = patientSecret;
        this.staffSecret = staffSecret;
        this.realmDecoders = new HashMap<>();
        initializeRealmDecoders();
    }

    /**
     * Initialise les décodeurs pour chaque realm avec les bonnes clés HMAC
     */
    private void initializeRealmDecoders() {
        log.info("Initializing HMAC JWT decoders for multiple realms");

        try {
            // Configuration des clés secrètes pour HS512
            SecretKeySpec adminKey = new SecretKeySpec(
                    adminSecret.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA512"
            );
            JwtDecoder adminDecoder = NimbusJwtDecoder.withSecretKey(adminKey).build();
            realmDecoders.put(LIMS_ADMIN_REALM, adminDecoder);
            log.info("Initialized HMAC JWT decoder for realm: {}", LIMS_ADMIN_REALM);

            SecretKeySpec patientKey = new SecretKeySpec(
                    patientSecret.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA512"
            );
            JwtDecoder patientDecoder = NimbusJwtDecoder.withSecretKey(patientKey).build();
            realmDecoders.put(LIMS_PATIENT_REALM, patientDecoder);
            log.info("Initialized HMAC JWT decoder for realm: {}", LIMS_PATIENT_REALM);

            SecretKeySpec staffKey = new SecretKeySpec(
                    staffSecret.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA512"
            );
            JwtDecoder staffDecoder = NimbusJwtDecoder.withSecretKey(staffKey).build();
            realmDecoders.put(LIMS_STAFF_REALM, staffDecoder);
            log.info("Initialized HMAC JWT decoder for realm: {}", LIMS_STAFF_REALM);

        } catch (Exception e) {
            log.error("Failed to initialize HMAC JWT decoders for realms: {}", e.getMessage(), e);
            throw new IllegalStateException("Cannot initialize multi-realm JWT decoder", e);
        }
    }

    /**
     * Décode le JWT en déterminant automatiquement le realm approprié
     */
    @Override
    public Jwt decode(String token) throws JwtException {
        log.debug("Attempting to decode JWT token");

        // Essayer de décoder avec chaque realm jusqu'à ce qu'un fonctionne
        JwtException lastException = null;

        // Ordre de priorité des realms pour l'optimisation
        String[] realmOrder = {LIMS_ADMIN_REALM, LIMS_PATIENT_REALM, LIMS_STAFF_REALM};

        for (String realm : realmOrder) {
            try {
                JwtDecoder decoder = realmDecoders.get(realm);
                if (decoder != null) {
                    log.debug("Trying to decode JWT with realm: {}", realm);
                    Jwt jwt = decoder.decode(token);

                    // Vérifier que le realm dans le token correspond
                    String jwtRealm = jwt.getClaimAsString("realm");
                    if (realm.equals(jwtRealm)) {
                        log.debug("Successfully decoded JWT from realm: {} for subject: {}", realm, jwt.getSubject());
                        return jwt;
                    } else {
                        log.debug("JWT realm claim '{}' doesn't match expected realm '{}'", jwtRealm, realm);
                    }
                }
            } catch (JwtException e) {
                log.debug("Failed to decode JWT with realm {}: {}", realm, e.getMessage());
                lastException = e;
            }
        }

        // Si aucun décodeur n'a fonctionné, lancer la dernière exception
        String errorMessage = "Failed to decode JWT with any supported realm. Last error: " +
                (lastException != null ? lastException.getMessage() : "Unknown error");
        log.error(errorMessage);
        throw new JwtException(errorMessage, lastException);
    }

    /**
     * Méthode utilitaire pour obtenir les realms supportés
     */
    public String[] getSupportedRealms() {
        return realmDecoders.keySet().toArray(new String[0]);
    }

    /**
     * Méthode pour vérifier si un realm est supporté
     */
    public boolean isRealmSupported(String realm) {
        return realmDecoders.containsKey(realm);
    }
}