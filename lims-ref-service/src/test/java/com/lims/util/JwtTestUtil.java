package com.lims.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;

/**
 * Utilitaire pour générer des tokens JWT de test pour le service référentiel.
 */
public class JwtTestUtil {

    private static final String TEST_SECRET = "lims-super-secret-key-for-development-only-change-in-production";

    /**
     * Génère un token JWT admin valide pour les tests
     */
    public static String generateValidAdminToken(String username) {
        return generateToken(username, "lims-admin", "ADMIN",
                Map.of("permissions", "SYSTEM_WIDE", "admin_level", "SUPER_ADMIN"));
    }

    /**
     * Génère un token JWT avec un realm invalide (pour tester le rejet)
     */
    public static String generateInvalidRealmToken(String username) {
        return generateToken(username, "lims-patient", "PATIENT",
                Map.of("patient_id", "12345"));
    }

    /**
     * Génère un token JWT avec un user_type invalide (pour tester le rejet)
     */
    public static String generateInvalidUserTypeToken(String username) {
        return generateToken(username, "lims-admin", "STAFF",
                Map.of("laboratory_id", "lab123"));
    }

    /**
     * Génère un token JWT expiré (pour tester le rejet)
     */
    public static String generateExpiredToken(String username) {
        SecretKeySpec secretKey = new SecretKeySpec(
                TEST_SECRET.getBytes(StandardCharsets.UTF_8),
                "HmacSHA512"
        );

        Instant now = Instant.now();

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(Date.from(now.minus(2, ChronoUnit.HOURS)))
                .setExpiration(Date.from(now.minus(1, ChronoUnit.HOURS))) // Expiré depuis 1h
                .claim("realm", "lims-admin")
                .claim("user_type", "ADMIN")
                .claim("email", username + "@lims.com")
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .compact();
    }

    private static String generateToken(String username, String realm, String userType,
                                        Map<String, Object> additionalClaims) {
        SecretKeySpec secretKey = new SecretKeySpec(
                TEST_SECRET.getBytes(StandardCharsets.UTF_8),
                "HmacSHA512"
        );

        Instant now = Instant.now();

        var builder = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plus(1, ChronoUnit.HOURS)))
                .claim("realm", realm)
                .claim("user_type", userType)
                .claim("email", username + "@lims.com");

        // Ajouter les claims supplémentaires
        additionalClaims.forEach(builder::claim);

        return builder.signWith(secretKey, SignatureAlgorithm.HS512).compact();
    }
}
