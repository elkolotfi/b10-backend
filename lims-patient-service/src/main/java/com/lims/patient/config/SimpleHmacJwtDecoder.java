package com.lims.patient.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Décodeur JWT simple utilisant directement JJWT (même lib que le service auth)
 */
@Slf4j
public class SimpleHmacJwtDecoder implements JwtDecoder {

    private final String jwtSecret;

    public SimpleHmacJwtDecoder(String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        try {
            log.debug("Decoding JWT token with JJWT library");

            // Utiliser directement la clé brute (comme dans le debug qui marche)
            SecretKeySpec secretKey = new SecretKeySpec(
                    jwtSecret.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA512"
            );
            log.debug("Using raw string secret key");

            // Décoder avec JJWT
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            log.debug("Successfully decoded JWT for subject: {}", claims.getSubject());

            // Vérifier que c'est un token admin pour ce service
            String realm = (String) claims.get("realm");
            if (!"lims-admin".equals(realm)) {
                log.debug("Token is not for admin realm: {}", realm);
                // Pour l'instant on accepte tous les realms, mais on pourrait filtrer ici
            }

            // Convertir en Spring Security Jwt
            return createSpringJwt(token, claims);

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

        Instant issuedAt = claims.getIssuedAt() != null ? claims.getIssuedAt().toInstant() : Instant.now();
        Instant expiresAt = claims.getExpiration() != null ? claims.getExpiration().toInstant() : Instant.now().plusSeconds(3600);

        return new Jwt(
                token,
                issuedAt,
                expiresAt,
                headers,
                claimsMap
        );
    }
}