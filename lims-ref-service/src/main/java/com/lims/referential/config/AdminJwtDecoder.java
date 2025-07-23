package com.lims.referential.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Décodeur JWT simple pour valider uniquement les tokens admin du realm lims-admin.
 * Ce service de référentiel n'accepte que les administrateurs.
 */
@Slf4j
public class AdminJwtDecoder implements JwtDecoder {

    private final String jwtSecret;

    public AdminJwtDecoder(String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        try {
            log.debug("Decoding JWT token for referential service");

            // Créer la clé secrète pour HMAC SHA512
            SecretKeySpec secretKey = new SecretKeySpec(
                    jwtSecret.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA512"
            );

            // Décoder avec JJWT
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            log.debug("JWT decoded successfully for subject: {}", claims.getSubject());

            // VALIDATION STRICTE : Vérifier que c'est un token admin
            String realm = (String) claims.get("realm");
            String userType = (String) claims.get("user_type");

            if (!"lims-admin".equals(realm)) {
                log.warn("Invalid realm for referential service: {}. Expected: lims-admin", realm);
                throw new JwtException("Invalid realm. Referential service only accepts admin tokens.");
            }

            if (!"ADMIN".equals(userType)) {
                log.warn("Invalid user type for referential service: {}. Expected: ADMIN", userType);
                throw new JwtException("Invalid user type. Referential service only accepts admin users.");
            }

            // Convertir en Spring Security Jwt
            return createSpringJwt(token, claims);

        } catch (JwtException e) {
            // Re-lancer les JwtException
            throw e;
        } catch (Exception e) {
            log.error("Failed to decode JWT: {}", e.getMessage());
            throw new JwtException("Failed to decode JWT", e);
        }
    }

    private Jwt createSpringJwt(String token, Claims claims) {
        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "HS512");
        headers.put("typ", "JWT");

        Map<String, Object> claimsMap = new HashMap<>(claims);

        Instant issuedAt = claims.getIssuedAt() != null ?
                claims.getIssuedAt().toInstant() : Instant.now();
        Instant expiresAt = claims.getExpiration() != null ?
                claims.getExpiration().toInstant() : Instant.now().plusSeconds(3600);

        return new Jwt(
                token,
                issuedAt,
                expiresAt,
                headers,
                claimsMap
        );
    }
}
