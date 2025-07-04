package com.lims.auth.service;

import com.lims.auth.config.LimsAuthProperties;
import com.lims.auth.exception.RateLimitException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class RateLimitService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final LimsAuthProperties authProperties;

    private static final String RATE_LIMIT_PREFIX = "rate_limit:";
    private static final String FAILED_ATTEMPTS_PREFIX = "failed_attempts:";
    private static final String LOCKOUT_PREFIX = "lockout:";

    /**
     * Vérifie et applique la limitation de taux pour un email donné
     */
    public void checkEmailRateLimit(String email) {
        String key = RATE_LIMIT_PREFIX + "email:" + email.toLowerCase();
        checkRateLimit(key, "email " + email);
    }

    /**
     * Vérifie et applique la limitation de taux pour une adresse IP donnée
     */
    public void checkIpRateLimit(String clientIp) {
        String key = RATE_LIMIT_PREFIX + "ip:" + clientIp;
        checkRateLimit(key, "IP " + clientIp);
    }

    /**
     * Vérifie et applique la limitation de taux pour un endpoint spécifique
     */
    public void checkEndpointRateLimit(String endpoint, String identifier) {
        String key = RATE_LIMIT_PREFIX + "endpoint:" + endpoint + ":" + identifier;
        checkRateLimit(key, "endpoint " + endpoint + " pour " + identifier);
    }

    /**
     * Incrémente le compteur de tentatives échouées pour un utilisateur
     */
    public void incrementFailedAttempts(String email) {
        String key = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();
        Long attempts = redisTemplate.opsForValue().increment(key);

        if (attempts == 1) {
            // Première tentative échouée, définir l'expiration
            redisTemplate.expire(key, authProperties.getRateLimit().getWindowMinutes(), TimeUnit.MINUTES);
        }

        log.warn("Tentative échouée pour {}: {} tentatives", email, attempts);

        // Vérifier si l'utilisateur doit être verrouillé
        if (attempts >= authProperties.getSecurity().getMaxFailedAttempts()) {
            lockoutUser(email);
        }
    }

    /**
     * Réinitialise le compteur de tentatives échouées pour un utilisateur
     */
    public void resetFailedAttempts(String email) {
        String key = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();
        redisTemplate.delete(key);

        // Supprimer aussi le verrouillage éventuel
        String lockoutKey = LOCKOUT_PREFIX + email.toLowerCase();
        redisTemplate.delete(lockoutKey);

        log.info("Compteur de tentatives échouées réinitialisé pour {}", email);
    }

    /**
     * Vérifie si un utilisateur est verrouillé
     */
    public boolean isUserLockedOut(String email) {
        String lockoutKey = LOCKOUT_PREFIX + email.toLowerCase();
        return redisTemplate.hasKey(lockoutKey);
    }

    /**
     * Obtient le nombre de tentatives échouées pour un utilisateur
     */
    public int getFailedAttempts(String email) {
        String key = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();
        Integer attempts = (Integer) redisTemplate.opsForValue().get(key);
        return attempts != null ? attempts : 0;
    }

    /**
     * Obtient le temps restant avant la réinitialisation du compteur
     */
    public long getRemainingLockoutTime(String email) {
        String lockoutKey = LOCKOUT_PREFIX + email.toLowerCase();
        Long ttl = redisTemplate.getExpire(lockoutKey, TimeUnit.SECONDS);
        return ttl != null ? ttl : 0;
    }

    /**
     * Vérifie si une action spécifique est autorisée pour un utilisateur
     */
    public void checkActionRateLimit(String email, String action) {
        String key = RATE_LIMIT_PREFIX + "action:" + action + ":" + email.toLowerCase();
        checkRateLimit(key, "action " + action + " pour " + email);
    }

    /**
     * Applique un verrouillage temporaire pour un utilisateur
     */
    public void lockoutUser(String email) {
        String lockoutKey = LOCKOUT_PREFIX + email.toLowerCase();
        redisTemplate.opsForValue().set(
                lockoutKey,
                System.currentTimeMillis(),
                authProperties.getSecurity().getLockoutDurationMinutes(),
                TimeUnit.MINUTES
        );

        log.warn("Utilisateur {} verrouillé temporairement pour {} minutes",
                email, authProperties.getSecurity().getLockoutDurationMinutes());
    }

    /**
     * Libère manuellement un utilisateur verrouillé
     */
    public void unlockUser(String email) {
        String lockoutKey = LOCKOUT_PREFIX + email.toLowerCase();
        String failedAttemptsKey = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();

        redisTemplate.delete(lockoutKey);
        redisTemplate.delete(failedAttemptsKey);

        log.info("Utilisateur {} déverrouillé manuellement", email);
    }

    /**
     * Vérifie la limitation de taux pour une clé donnée
     */
    private void checkRateLimit(String key, String description) {
        Long attempts = redisTemplate.opsForValue().increment(key);

        if (attempts == 1) {
            // Première tentative, définir l'expiration
            redisTemplate.expire(key, authProperties.getRateLimit().getWindowMinutes(), TimeUnit.MINUTES);
        }

        if (attempts > authProperties.getRateLimit().getMaxAttempts()) {
            long remainingTime = redisTemplate.getExpire(key, TimeUnit.SECONDS);

            log.warn("Rate limit dépassé pour {}: {} tentatives", description, attempts);

            throw new RateLimitException(
                    String.format("Trop de tentatives pour %s. Réessayez dans %d minutes.",
                            description, remainingTime / 60),
                    0,
                    remainingTime * 1000
            );
        }

        log.debug("Rate limit OK pour {}: {}/{} tentatives",
                description, attempts, authProperties.getRateLimit().getMaxAttempts());
    }

    /**
     * Obtient les statistiques de limitation de taux pour un utilisateur
     */
    public RateLimitStatus getRateLimitStatus(String email) {
        String emailKey = RATE_LIMIT_PREFIX + "email:" + email.toLowerCase();
        String failedAttemptsKey = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();
        String lockoutKey = LOCKOUT_PREFIX + email.toLowerCase();

        Integer currentAttempts = (Integer) redisTemplate.opsForValue().get(emailKey);
        Integer failedAttempts = (Integer) redisTemplate.opsForValue().get(failedAttemptsKey);
        boolean isLockedOut = redisTemplate.hasKey(lockoutKey);

        long remainingTime = 0;
        if (isLockedOut) {
            remainingTime = redisTemplate.getExpire(lockoutKey, TimeUnit.SECONDS);
        }

        return RateLimitStatus.builder()
                .currentAttempts(currentAttempts != null ? currentAttempts : 0)
                .maxAttempts(authProperties.getRateLimit().getMaxAttempts())
                .failedAttempts(failedAttempts != null ? failedAttempts : 0)
                .maxFailedAttempts(authProperties.getSecurity().getMaxFailedAttempts())
                .isLockedOut(isLockedOut)
                .remainingLockoutTimeSeconds(remainingTime)
                .build();
    }

    /**
     * Nettoie les anciens enregistrements de limitation de taux
     */
    public void cleanup() {
        // Cette méthode pourrait être appelée par un scheduler
        // pour nettoyer les anciennes entrées expirées
        log.debug("Nettoyage des limitations de taux expiré");
    }

    @lombok.Data
    @lombok.Builder
    public static class RateLimitStatus {
        private int currentAttempts;
        private int maxAttempts;
        private int failedAttempts;
        private int maxFailedAttempts;
        private boolean isLockedOut;
        private long remainingLockoutTimeSeconds;

        public boolean isNearLimit() {
            return currentAttempts >= (maxAttempts * 0.8);
        }

        public boolean isAtLimit() {
            return currentAttempts >= maxAttempts;
        }

        public int getRemainingAttempts() {
            return Math.max(0, maxAttempts - currentAttempts);
        }
    }
}