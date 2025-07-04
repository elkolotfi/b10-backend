package com.lims.auth.service;

import com.lims.auth.config.LimsAuthProperties;
import com.lims.auth.dto.request.AdminLoginRequest;
import com.lims.auth.dto.response.AdminLoginResponse;
import com.lims.auth.dto.response.AdminUserResponse;
import com.lims.auth.entity.AdminSession;
import com.lims.auth.entity.AdminUser;
import com.lims.auth.entity.MfaSecret;
import com.lims.auth.exception.AccountLockedException;
import com.lims.auth.exception.AuthenticationException;
import com.lims.auth.exception.RateLimitException;
import com.lims.auth.mapper.AdminUserMapper;
import com.lims.auth.repository.AdminSessionRepository;
import com.lims.auth.repository.AdminUserRepository;
import com.lims.auth.repository.MfaSecretRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminAuthenticationService {

    private final AdminUserRepository adminUserRepository;
    private final AdminSessionRepository adminSessionRepository;
    private final MfaSecretRepository mfaSecretRepository;
    private final AdminMfaService adminMfaService;
    private final AdminTokenService adminTokenService;
    private final RateLimitService rateLimitService;
    private final AdminUserMapper adminUserMapper;
    private final PasswordEncoder passwordEncoder;
    private final RedisTemplate<String, Object> redisTemplate;
    private final LimsAuthProperties authProperties;
    private final KeycloakAdminService keycloakAdminService;

    private static final String RATE_LIMIT_PREFIX = "auth:rate_limit:";
    private static final String FAILED_ATTEMPTS_PREFIX = "auth:failed_attempts:";
    private static final String LOCKOUT_PREFIX = "auth:lockout:";

    @Transactional
    public AdminLoginResponse authenticate(AdminLoginRequest request, String clientIp, String userAgent) {

        // 1. Vérifier le rate limiting
        checkRateLimit(request.getEmail(), clientIp);

        // 2. Récupérer l'utilisateur
        AdminUser adminUser = adminUserRepository.findByEmailIgnoreCase(request.getEmail())
                .orElseThrow(() -> new AuthenticationException("Identifiants invalides"));

        // 3. Vérifier le statut du compte
        validateAccountStatus(adminUser);

        // 4. Vérifier les tentatives échouées
        checkFailedAttempts(adminUser);

        try {
            // 5. Authentification via Keycloak
            String keycloakToken = keycloakAdminService.authenticate(request.getEmail(), request.getPassword());

            // 6. Vérifier si MFA est configuré
            Optional<MfaSecret> mfaSecret = mfaSecretRepository.findByAdminUserIdAndActiveTrue(adminUser.getId());

            if (mfaSecret.isEmpty()) {
                // Premier login - Setup MFA requis
                String setupToken = generateMfaSetupToken(adminUser);

                log.info("Premier login détecté pour admin: {} - Setup MFA requis", request.getEmail());
                return AdminLoginResponse.mfaSetupRequired(setupToken);
            }

            // 7. Vérifier le code OTP si fourni
            if (request.getOtpCode() != null && !request.getOtpCode().trim().isEmpty()) {
                boolean otpValid = adminMfaService.validateOtpCode(
                        adminUser.getId(),
                        request.getOtpCode().trim()
                );

                if (!otpValid) {
                    incrementFailedAttempts(adminUser);
                    throw new AuthenticationException("Code OTP invalide");
                }

                // 8. Connexion réussie - Génération des tokens
                return completeAuthentication(adminUser, clientIp, userAgent, keycloakToken);

            } else {
                // Code OTP manquant
                throw new AuthenticationException("Code OTP requis");
            }

        } catch (Exception e) {
            // Incrémenter les tentatives échouées
            incrementFailedAttempts(adminUser);

            // Enregistrer la tentative dans les logs d'audit
            logFailedAttempt(adminUser, clientIp, userAgent, e.getMessage());

            if (e instanceof AuthenticationException) {
                throw e;
            }

            throw new AuthenticationException("Erreur lors de l'authentification");
        }
    }

    private void validateLocalPassword(AdminUser adminUser, String password) {
        // En mode de développement ou si pas de mot de passe hashé, utiliser un mot de passe par défaut
        String storedPassword = adminUser.getKeycloakId(); // Utiliser keycloakId comme stockage temporaire
        if (storedPassword == null || storedPassword.isEmpty()) {
            // Mot de passe par défaut pour le développement
            if (!"dev_password_123".equals(password)) {
                throw new AuthenticationException("Identifiants invalides");
            }
        } else {
            // Vérifier le mot de passe hashé
            if (!passwordEncoder.matches(password, storedPassword)) {
                throw new AuthenticationException("Identifiants invalides");
            }
        }
    }

    private void checkRateLimit(String email, String clientIp) {
        String emailKey = RATE_LIMIT_PREFIX + "email:" + email;
        String ipKey = RATE_LIMIT_PREFIX + "ip:" + clientIp;

        // Vérifier rate limiting par email
        Integer emailAttempts = (Integer) redisTemplate.opsForValue().get(emailKey);
        if (emailAttempts != null && emailAttempts >= authProperties.getRateLimit().getMaxAttempts()) {
            log.warn("Rate limit dépassé pour email: {}", email);
            throw new RateLimitException("Trop de tentatives de connexion pour cet email");
        }

        // Vérifier rate limiting par IP
        Integer ipAttempts = (Integer) redisTemplate.opsForValue().get(ipKey);
        if (ipAttempts != null && ipAttempts >= authProperties.getRateLimit().getMaxAttempts()) {
            log.warn("Rate limit dépassé pour IP: {}", clientIp);
            throw new RateLimitException("Trop de tentatives de connexion depuis cette adresse IP");
        }

        // Incrémenter les compteurs
        redisTemplate.opsForValue().increment(emailKey);
        redisTemplate.expire(emailKey, authProperties.getRateLimit().getWindowMinutes(), TimeUnit.MINUTES);

        redisTemplate.opsForValue().increment(ipKey);
        redisTemplate.expire(ipKey, authProperties.getRateLimit().getWindowMinutes(), TimeUnit.MINUTES);
    }

    private void validateAccountStatus(AdminUser adminUser) {
        if (!adminUser.isEnabled()) {
            throw new AuthenticationException("Compte désactivé");
        }

        if (adminUser.getLockedUntil() != null && adminUser.getLockedUntil().isAfter(LocalDateTime.now())) {
            throw new AccountLockedException("Compte temporairement verrouillé jusqu'à " + adminUser.getLockedUntil());
        }
    }

    private void checkFailedAttempts(AdminUser adminUser) {
        if (adminUser.getFailedAttempts() >= authProperties.getSecurity().getMaxFailedAttempts()) {
            // Verrouiller le compte temporairement
            LocalDateTime lockUntil = LocalDateTime.now().plusMinutes(authProperties.getSecurity().getLockoutDurationMinutes());
            adminUser.setLockedUntil(lockUntil);
            adminUser.setFailedAttempts(0);
            adminUserRepository.save(adminUser);

            throw new AccountLockedException("Compte verrouillé temporairement suite à trop de tentatives échouées");
        }
    }

    private String generateMfaSetupToken(AdminUser adminUser) {
        String setupToken = UUID.randomUUID().toString();

        // Stocker le token temporairement dans Redis
        String key = "mfa_setup_token:" + setupToken;
        redisTemplate.opsForValue().set(key, adminUser.getId(), authProperties.getMfa().getSetupTokenExpiry(), TimeUnit.SECONDS);

        return setupToken;
    }

    private void incrementFailedAttempts(AdminUser adminUser) {
        adminUser.setFailedAttempts(adminUser.getFailedAttempts() + 1);
        adminUserRepository.save(adminUser);

        log.warn("Tentative de connexion échouée pour admin: {} - Tentatives: {}",
                adminUser.getEmail(), adminUser.getFailedAttempts());
    }

    private AdminLoginResponse completeAuthentication(AdminUser adminUser, String clientIp,
                                                      String userAgent, String keycloakToken) {

        // Réinitialiser les tentatives échouées
        adminUser.setFailedAttempts(0);
        adminUser.setLockedUntil(null);
        adminUser.setLastLogin(LocalDateTime.now());
        adminUser.setLastLoginIp(clientIp);
        adminUserRepository.save(adminUser);

        // Créer une nouvelle session
        AdminSession session = createAdminSession(adminUser, clientIp, userAgent);

        // Générer les tokens JWT
        String accessToken = adminTokenService.generateAccessToken(adminUser, session);
        String refreshToken = adminTokenService.generateRefreshToken(adminUser, session);

        // Construire la réponse
        AdminLoginResponse.AdminUserInfo userInfo = AdminLoginResponse.AdminUserInfo.builder()
                .id(adminUser.getId())
                .email(adminUser.getEmail())
                .firstName(adminUser.getFirstName())
                .lastName(adminUser.getLastName())
                .role(adminUser.getRole().name())
                .realm("lims-admin")
                .userType("ADMIN")
                .permissions(adminUser.getPermissions())
                .mfaEnabled(true)
                .lastLogin(adminUser.getLastLogin())
                .status(adminUser.getStatus().name())
                .build();

        log.info("Connexion admin réussie - Email: {}, SessionId: {}, Mode: Keycloak",
                adminUser.getEmail(), session.getId());

        return AdminLoginResponse.success(accessToken, refreshToken, session.getId(), userInfo);
    }

    private AdminSession createAdminSession(AdminUser adminUser, String clientIp, String userAgent) {
        AdminSession session = AdminSession.builder()
                .id(UUID.randomUUID().toString())
                .adminUser(adminUser)
                .clientIp(clientIp)
                .userAgent(userAgent)
                .createdAt(LocalDateTime.now())
                .lastActivity(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusSeconds(authProperties.getSession().getTimeout()))
                .active(true)
                .build();

        return adminSessionRepository.save(session);
    }

    public AdminUserResponse getCurrentAdmin(String adminId) {
        AdminUser adminUser = adminUserRepository.findById(adminId)
                .orElseThrow(() -> new AuthenticationException("Administrateur non trouvé"));

        return adminUserMapper.toResponse(adminUser);
    }

    public Map<String, Object> getAdminPermissions(String adminId) {
        AdminUser adminUser = adminUserRepository.findById(adminId)
                .orElseThrow(() -> new AuthenticationException("Administrateur non trouvé"));

        return Map.of(
                "permissions", adminUser.getPermissions(),
                "role", adminUser.getRole().name(),
                "realm", "lims-admin",
                "keycloakEnabled", keycloakAdminService != null
        );
    }

    @Transactional
    public void logout(String adminId, String sessionId, String clientIp) {
        // Invalider la session
        adminSessionRepository.findByIdAndAdminUserIdAndActiveTrue(sessionId, adminId)
                .ifPresent(session -> {
                    session.setActive(false);
                    session.setLogoutAt(LocalDateTime.now());
                    adminSessionRepository.save(session);
                });

        // Invalider les tokens dans Redis
        adminTokenService.invalidateTokens(adminId, sessionId);

        log.info("Déconnexion admin - AdminId: {}, SessionId: {}, IP: {}", adminId, sessionId, clientIp);
    }

    /**
     * Méthode pour créer un utilisateur admin de développement
     */
    @Transactional
    public AdminUser createDevelopmentAdmin(String email, String firstName, String lastName) {
        if (adminUserRepository.existsByEmailIgnoreCase(email)) {
            return adminUserRepository.findByEmailIgnoreCase(email).orElseThrow();
        }

        AdminUser adminUser = AdminUser.builder()
                .id(UUID.randomUUID().toString())
                .email(email)
                .firstName(firstName)
                .lastName(lastName)
                .role(AdminUser.AdminRole.SUPER_ADMIN)
                .permissions(java.util.List.of("SYSTEM_ADMIN", "USER_MANAGEMENT", "AUDIT_READ"))
                .enabled(true)
                .status(AdminUser.AdminStatus.ACTIVE)
                .mfaEnabled(false)
                .failedAttempts(0)
                .createdBy("system")
                .createdAt(LocalDateTime.now())
                .build();

        adminUser = adminUserRepository.save(adminUser);

        log.info("Utilisateur admin de développement créé: {}", email);
        return adminUser;
    }

    private void logFailedAttempt(AdminUser adminUser, String clientIp, String userAgent, String reason) {
        log.warn("Tentative de connexion échouée - Email: {}, IP: {}, UserAgent: {}, Raison: {}",
                adminUser.getEmail(), clientIp, userAgent, reason);

        // Ici on pourrait envoyer un événement à un système d'audit
        // ou enregistrer dans une table d'audit dédiée
    }
}