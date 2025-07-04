package com.lims.auth.service;

import com.lims.auth.config.LimsAuthProperties;
import com.lims.auth.dto.response.AdminTokenResponse;
import com.lims.auth.entity.AdminSession;
import com.lims.auth.entity.AdminUser;
import com.lims.auth.exception.AuthenticationException;
import com.lims.auth.repository.AdminSessionRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminTokenService {

    private final AdminSessionRepository adminSessionRepository;
    private final RedisTemplate<String, Object> redisTemplate;
    private final LimsAuthProperties authProperties;

    @Value("${lims.auth.jwt.secret:default-secret-key-for-development-only-change-in-production}")
    private String jwtSecret;

    @Value("${lims.auth.jwt.access-token-validity:3600}")
    private int accessTokenValiditySeconds;

    @Value("${lims.auth.jwt.refresh-token-validity:86400}")
    private int refreshTokenValiditySeconds;

    private static final String TOKEN_PREFIX = "admin_token:";
    private static final String REFRESH_TOKEN_PREFIX = "admin_refresh:";
    private static final String SESSION_PREFIX = "admin_session:";
    private static final String BLACKLIST_PREFIX = "admin_blacklist:";

    public String generateAccessToken(AdminUser adminUser, String sessionId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + accessTokenValiditySeconds * 1000L);

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", adminUser.getId());
        claims.put("email", adminUser.getEmail());
        claims.put("realm", "lims-admin");
        claims.put("user_type", "ADMIN");
        claims.put("role", adminUser.getRole().name());
        claims.put("permissions", adminUser.getPermissions());
        claims.put("session_id", sessionId);
        claims.put("mfa_verified", true);
        claims.put("iat", now.getTime() / 1000);
        claims.put("exp", expiryDate.getTime() / 1000);

        String token = Jwts.builder()
                .claims(claims)
                .issuer("lims-auth-service")
                .subject(adminUser.getId())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey(), Jwts.SIG.HS512)
                .compact();

        // Stocker le token dans Redis pour validation
        String tokenKey = TOKEN_PREFIX + adminUser.getId() + ":" + sessionId;
        redisTemplate.opsForValue().set(tokenKey, token, accessTokenValiditySeconds, TimeUnit.SECONDS);

        log.debug("Token d'accès généré pour admin: {} - Session: {}", adminUser.getEmail(), sessionId);

        return token;
    }

    public String generateAccessToken(AdminUser adminUser, AdminSession session) {
        return generateAccessToken(adminUser, session.getId());
    }

    public String generateRefreshToken(AdminUser adminUser, String sessionId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + refreshTokenValiditySeconds * 1000L);

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", adminUser.getId());
        claims.put("email", adminUser.getEmail());
        claims.put("session_id", sessionId);
        claims.put("type", "refresh");
        claims.put("iat", now.getTime() / 1000);
        claims.put("exp", expiryDate.getTime() / 1000);

        String refreshToken = Jwts.builder()
                .claims(claims)
                .issuer("lims-auth-service")
                .subject(adminUser.getId())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey(), Jwts.SIG.HS512)
                .compact();

        // Stocker le refresh token dans Redis
        String refreshKey = REFRESH_TOKEN_PREFIX + adminUser.getId() + ":" + sessionId;
        redisTemplate.opsForValue().set(refreshKey, refreshToken, refreshTokenValiditySeconds, TimeUnit.SECONDS);

        log.debug("Token de rafraîchissement généré pour admin: {} - Session: {}", adminUser.getEmail(), sessionId);

        return refreshToken;
    }

    public String generateRefreshToken(AdminUser adminUser, AdminSession session) {
        return generateRefreshToken(adminUser, session.getId());
    }

    public AdminTokenResponse refreshToken(String refreshToken, String clientIp) {
        try {
            // Vérifier si le token est en blacklist
            if (isTokenBlacklisted(refreshToken)) {
                throw new AuthenticationException("Token révoqué");
            }

            // Décoder et valider le refresh token
            Claims claims = validateAndParseToken(refreshToken);

            String adminId = claims.getSubject();
            String sessionId = claims.get("session_id", String.class);

            // Vérifier que c'est bien un refresh token
            if (!"refresh".equals(claims.get("type"))) {
                throw new AuthenticationException("Type de token invalide");
            }

            // Vérifier que la session est toujours active
            AdminSession session = adminSessionRepository.findByIdAndAdminUserIdAndActiveTrue(sessionId, adminId)
                    .orElseThrow(() -> new AuthenticationException("Session invalide ou expirée"));

            // Mettre à jour l'activité de la session
            session.setLastActivity(LocalDateTime.now());
            adminSessionRepository.save(session);

            // Générer de nouveaux tokens
            String newAccessToken = generateAccessToken(session.getAdminUser(), sessionId);
            String newRefreshToken = generateRefreshToken(session.getAdminUser(), sessionId);

            // Invalider l'ancien refresh token
            blacklistToken(refreshToken);

            log.info("Tokens rafraîchis pour admin: {} - Session: {}", session.getAdminUser().getEmail(), sessionId);

            return AdminTokenResponse.success(newAccessToken, newRefreshToken, (long) accessTokenValiditySeconds);

        } catch (ExpiredJwtException e) {
            log.warn("Tentative d'utilisation d'un refresh token expiré");
            throw new AuthenticationException("Token expiré");
        } catch (JwtException e) {
            log.error("Erreur validation refresh token", e);
            throw new AuthenticationException("Token invalide");
        }
    }

    public boolean validateToken(String token) {
        try {
            if (isTokenBlacklisted(token)) {
                return false;
            }

            validateAndParseToken(token);
            return true;
        } catch (JwtException e) {
            log.debug("Token invalide: {}", e.getMessage());
            return false;
        }
    }

    public Claims validateAndParseToken(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Map<String, Object> getSessionStatus(String adminId) {
        // Récupérer les sessions actives
        List<AdminSession> activeSessions = adminSessionRepository.findByAdminUserIdAndActiveTrue(adminId);

        if (activeSessions.isEmpty()) {
            return Map.of(
                    "hasActiveSession", false,
                    "sessionCount", 0
            );
        }

        AdminSession currentSession = activeSessions.get(0); // Prendre la plus récente

        return Map.of(
                "hasActiveSession", true,
                "sessionCount", activeSessions.size(),
                "sessionId", currentSession.getId(),
                "isActive", currentSession.isActive(),
                "createdAt", currentSession.getCreatedAt(),
                "lastActivity", currentSession.getLastActivity(),
                "expiresAt", currentSession.getExpiresAt(),
                "clientIp", currentSession.getClientIp()
        );
    }

    public void invalidateTokens(String adminId, String sessionId) {
        // Mettre en blacklist tous les tokens de cette session
        String tokenPattern = TOKEN_PREFIX + adminId + ":" + sessionId;
        String refreshPattern = REFRESH_TOKEN_PREFIX + adminId + ":" + sessionId;

        // Récupérer les tokens depuis Redis
        String accessToken = (String) redisTemplate.opsForValue().get(tokenPattern);
        String refreshToken = (String) redisTemplate.opsForValue().get(refreshPattern);

        if (accessToken != null) {
            blacklistToken(accessToken);
        }

        if (refreshToken != null) {
            blacklistToken(refreshToken);
        }

        // Supprimer les tokens du cache
        redisTemplate.delete(tokenPattern);
        redisTemplate.delete(refreshPattern);

        log.info("Tokens invalidés pour admin: {} - Session: {}", adminId, sessionId);
    }

    public void invalidateAllUserTokens(String adminId) {
        // Récupérer toutes les sessions actives
        List<AdminSession> activeSessions = adminSessionRepository.findByAdminUserIdAndActiveTrue(adminId);

        for (AdminSession session : activeSessions) {
            invalidateTokens(adminId, session.getId());

            // Désactiver la session
            session.setActive(false);
            session.setLogoutAt(LocalDateTime.now());
            adminSessionRepository.save(session);
        }

        log.info("Tous les tokens invalidés pour admin: {}", adminId);
    }

    private void blacklistToken(String token) {
        try {
            Claims claims = validateAndParseToken(token);
            Date expiration = claims.getExpiration();

            long timeToLive = expiration.getTime() - System.currentTimeMillis();
            if (timeToLive > 0) {
                String blacklistKey = BLACKLIST_PREFIX + getTokenId(token);
                redisTemplate.opsForValue().set(blacklistKey, "blacklisted", timeToLive, TimeUnit.MILLISECONDS);
            }
        } catch (Exception e) {
            log.warn("Erreur lors de la mise en blacklist du token", e);
        }
    }

    private boolean isTokenBlacklisted(String token) {
        String blacklistKey = BLACKLIST_PREFIX + getTokenId(token);
        return Boolean.TRUE.equals(redisTemplate.hasKey(blacklistKey));
    }

    private String getTokenId(String token) {
        try {
            Claims claims = validateAndParseToken(token);
            return claims.getSubject() + ":" + claims.get("session_id", String.class) + ":" + claims.getIssuedAt().getTime();
        } catch (Exception e) {
            return token.substring(Math.max(0, token.length() - 10));
        }
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractAdminId(String token) {
        Claims claims = validateAndParseToken(token);
        return claims.getSubject();
    }

    public String extractSessionId(String token) {
        Claims claims = validateAndParseToken(token);
        return claims.get("session_id", String.class);
    }

    public List<String> extractPermissions(String token) {
        Claims claims = validateAndParseToken(token);
        return claims.get("permissions", List.class);
    }

    public boolean isTokenExpired(String token) {
        try {
            Claims claims = validateAndParseToken(token);
            return claims.getExpiration().before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        } catch (JwtException e) {
            return true;
        }
    }

    public long getTokenRemainingTime(String token) {
        try {
            Claims claims = validateAndParseToken(token);
            long expiration = claims.getExpiration().getTime();
            long current = System.currentTimeMillis();
            return Math.max(0, expiration - current) / 1000;
        } catch (JwtException e) {
            return 0;
        }
    }
}