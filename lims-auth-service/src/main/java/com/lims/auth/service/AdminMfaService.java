package com.lims.auth.service;

import com.lims.auth.dto.request.AdminMfaVerifyRequest;
import com.lims.auth.dto.response.AdminLoginResponse;
import com.lims.auth.dto.response.AdminMfaSetupResponse;
import com.lims.auth.entity.AdminUser;
import com.lims.auth.entity.MfaSecret;
import com.lims.auth.entity.MfaBackupCode;
import com.lims.auth.repository.AdminUserRepository;
import com.lims.auth.repository.MfaSecretRepository;
import com.lims.auth.repository.MfaBackupCodeRepository;
import com.lims.auth.exception.MfaException;
import com.lims.auth.exception.AuthenticationException;
import com.lims.auth.config.LimsAuthProperties;

import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminMfaService {

    private final AdminUserRepository adminUserRepository;
    private final MfaSecretRepository mfaSecretRepository;
    private final MfaBackupCodeRepository mfaBackupCodeRepository;
    private final AdminTokenService adminTokenService;
    private final RedisTemplate<String, Object> redisTemplate;
    private final LimsAuthProperties authProperties;
    private final SecretGenerator secretGenerator;

    private final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeVerifier codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

    private static final String MFA_SETUP_TOKEN_PREFIX = "mfa_setup_token:";
    private static final String MFA_TEMP_SECRET_PREFIX = "mfa_temp_secret:";
    private static final String QR_CODE_SIZE = "200x200";
    private static final int QR_CODE_MARGIN = 1;

    @Transactional
    public AdminMfaSetupResponse generateMfaSetup(String setupToken) {

        // Récupérer l'ID admin depuis Redis
        String adminId = (String) redisTemplate.opsForValue().get(MFA_SETUP_TOKEN_PREFIX + setupToken);
        if (adminId == null) {
            throw new MfaException("Token de setup invalide ou expiré");
        }

        // Récupérer l'utilisateur
        AdminUser adminUser = adminUserRepository.findById(adminId)
                .orElseThrow(() -> new MfaException("Utilisateur non trouvé"));

        // Vérifier qu'il n'y a pas déjà un MFA configuré
        Optional<MfaSecret> existingSecret = mfaSecretRepository.findByAdminUserIdAndActiveTrue(adminId);
        if (existingSecret.isPresent()) {
            throw new MfaException("MFA déjà configuré pour cet utilisateur");
        }

        try {
            // Générer le secret TOTP
            String secret = secretGenerator.generate();

            // Stocker temporairement le secret (10 minutes)
            String tempSecretKey = MFA_TEMP_SECRET_PREFIX + setupToken;
            redisTemplate.opsForValue().set(tempSecretKey, secret, 10, TimeUnit.MINUTES);

            // Générer l'URL et le QR Code
            String qrCodeUrl = generateQrCodeUrl(adminUser.getEmail(), secret);
            String qrCodeImage = generateQrCodeImage(qrCodeUrl);

            log.info("QR Code MFA généré pour admin: {}", adminUser.getEmail());

            return AdminMfaSetupResponse.success(
                    qrCodeImage,
                    qrCodeUrl,
                    secret, // Ne pas exposer en production
                    authProperties.getMfa().getIssuer()
            );

        } catch (Exception e) {
            log.error("Erreur génération QR Code MFA pour admin: {}", adminUser.getEmail(), e);
            throw new MfaException("Erreur lors de la génération du QR Code");
        }
    }

    @Transactional
    public AdminLoginResponse verifyMfaSetup(AdminMfaVerifyRequest request, String clientIp, String userAgent) {

        // Récupérer l'ID admin depuis Redis
        String adminId = (String) redisTemplate.opsForValue().get(MFA_SETUP_TOKEN_PREFIX + request.getSetupToken());
        if (adminId == null) {
            throw new MfaException("Token de setup invalide ou expiré");
        }

        // Récupérer le secret temporaire
        String tempSecretKey = MFA_TEMP_SECRET_PREFIX + request.getSetupToken();
        String secret = (String) redisTemplate.opsForValue().get(tempSecretKey);
        if (secret == null) {
            throw new MfaException("Secret temporaire non trouvé ou expiré");
        }

        // Récupérer l'utilisateur
        AdminUser adminUser = adminUserRepository.findById(adminId)
                .orElseThrow(() -> new MfaException("Utilisateur non trouvé"));

        // Vérifier le code OTP
        if (!codeVerifier.isValidCode(secret, request.getOtpCode())) {
            log.warn("Code OTP invalide lors du setup MFA pour admin: {}", adminUser.getEmail());
            throw new MfaException("Code OTP invalide");
        }

        try {
            // Sauvegarder le secret MFA définitivement
            MfaSecret mfaSecret = MfaSecret.builder()
                    .adminUser(adminUser)
                    .secret(secret)
                    .active(true)
                    .createdAt(LocalDateTime.now())
                    .build();
            mfaSecretRepository.save(mfaSecret);

            // Générer les codes de récupération
            List<String> backupCodes = generateBackupCodes(adminUser);

            // Nettoyer les données temporaires
            redisTemplate.delete(MFA_SETUP_TOKEN_PREFIX + request.getSetupToken());
            redisTemplate.delete(tempSecretKey);

            // Mettre à jour le statut utilisateur
            adminUser.setMfaEnabled(true);
            adminUser.setMfaSetupAt(LocalDateTime.now());
            adminUserRepository.save(adminUser);

            // Créer la session et connecter automatiquement
            return completeAuthenticationAfterMfaSetup(adminUser, clientIp, userAgent, backupCodes);

        } catch (Exception e) {
            log.error("Erreur finalisation setup MFA pour admin: {}", adminUser.getEmail(), e);
            throw new MfaException("Erreur lors de la finalisation du setup MFA");
        }
    }

    public boolean validateOtpCode(String adminId, String otpCode) {

        // Récupérer le secret MFA
        MfaSecret mfaSecret = mfaSecretRepository.findByAdminUserIdAndActiveTrue(adminId)
                .orElseThrow(() -> new MfaException("MFA non configuré"));

        // Vérifier le code OTP
        boolean isValid = codeVerifier.isValidCode(mfaSecret.getSecret(), otpCode);

        if (!isValid) {
            log.warn("Code OTP invalide pour admin: {}", adminId);

            // Vérifier si c'est un code de récupération
            return validateBackupCode(adminId, otpCode);
        }

        return true;
    }

    private boolean validateBackupCode(String adminId, String backupCode) {

        Optional<MfaBackupCode> backupCodeEntity = mfaBackupCodeRepository
                .findByAdminUserIdAndCodeAndUsedFalse(adminId, backupCode);

        if (backupCodeEntity.isPresent()) {
            // Marquer le code comme utilisé
            MfaBackupCode code = backupCodeEntity.get();
            code.setUsed(true);
            code.setUsedAt(LocalDateTime.now());
            mfaBackupCodeRepository.save(code);

            log.info("Code de récupération MFA utilisé pour admin: {}", adminId);
            return true;
        }

        return false;
    }

    private List<String> generateBackupCodes(AdminUser adminUser) {

        // Supprimer les anciens codes
        mfaBackupCodeRepository.deleteByAdminUserId(adminUser.getId());

        List<String> backupCodes = new ArrayList<>();
        SecureRandom random = new SecureRandom();

        for (int i = 0; i < authProperties.getMfa().getBackupCodes().getCount(); i++) {
            String code = generateBackupCode(random);
            backupCodes.add(code);

            MfaBackupCode backupCodeEntity = MfaBackupCode.builder()
                    .adminUser(adminUser)
                    .code(code)
                    .used(false)
                    .createdAt(LocalDateTime.now())
                    .build();

            mfaBackupCodeRepository.save(backupCodeEntity);
        }

        log.info("Codes de récupération MFA générés pour admin: {} - Nombre: {}",
                adminUser.getEmail(), backupCodes.size());

        return backupCodes;
    }

    private String generateBackupCode(SecureRandom random) {
        StringBuilder code = new StringBuilder();
        int length = authProperties.getMfa().getBackupCodes().getLength();

        for (int i = 0; i < length; i++) {
            code.append(random.nextInt(10));
        }

        return code.toString();
    }

    private String generateQrCodeUrl(String email, String secret) {
        String issuer = authProperties.getMfa().getIssuer();
        String accountName = email;

        return String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
                URLEncoder.encode(issuer, StandardCharsets.UTF_8),
                URLEncoder.encode(accountName, StandardCharsets.UTF_8),
                secret,
                URLEncoder.encode(issuer, StandardCharsets.UTF_8)
        );
    }

    private String generateQrCodeImage(String qrCodeUrl) throws WriterException, IOException {

        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        Map<EncodeHintType, Object> hints = new HashMap<>();
        hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
        hints.put(EncodeHintType.MARGIN, QR_CODE_MARGIN);

        BitMatrix bitMatrix = qrCodeWriter.encode(qrCodeUrl, BarcodeFormat.QR_CODE, 200, 200, hints);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);

        byte[] qrCodeBytes = outputStream.toByteArray();
        return Base64.getEncoder().encodeToString(qrCodeBytes);
    }

    private AdminLoginResponse completeAuthenticationAfterMfaSetup(AdminUser adminUser, String clientIp,
                                                                   String userAgent, List<String> backupCodes) {

        // Créer une session temporaire pour finaliser l'authentification
        // Cette logique devrait être similaire à celle du service d'authentification

        // Mettre à jour les informations de connexion
        adminUser.setLastLogin(LocalDateTime.now());
        adminUser.setLastLoginIp(clientIp);
        adminUserRepository.save(adminUser);

        // Créer une session
        String sessionId = UUID.randomUUID().toString();

        // Générer les tokens
        String accessToken = adminTokenService.generateAccessToken(adminUser, sessionId);
        String refreshToken = adminTokenService.generateRefreshToken(adminUser, sessionId);

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

        AdminLoginResponse response = AdminLoginResponse.success(accessToken, refreshToken, sessionId, userInfo);
        response.setBackupCodes(backupCodes);

        log.info("Setup MFA complété et connexion automatique pour admin: {}", adminUser.getEmail());

        return response;
    }

    public List<String> getBackupCodes(String adminId) {
        return mfaBackupCodeRepository.findByAdminUserIdAndUsedFalse(adminId)
                .stream()
                .map(MfaBackupCode::getCode)
                .collect(Collectors.toList());
    }

    @Transactional
    public List<String> regenerateBackupCodes(String adminId, String otpCode) {

        // Vérifier le code OTP avant de régénérer
        if (!validateOtpCode(adminId, otpCode)) {
            throw new MfaException("Code OTP invalide");
        }

        AdminUser adminUser = adminUserRepository.findById(adminId)
                .orElseThrow(() -> new AuthenticationException("Utilisateur non trouvé"));

        // Générer de nouveaux codes
        List<String> newBackupCodes = generateBackupCodes(adminUser);

        log.info("Codes de récupération MFA régénérés pour admin: {}", adminUser.getEmail());

        return newBackupCodes;
    }

    public Map<String, Object> getMfaStatus(String adminId) {

        AdminUser adminUser = adminUserRepository.findById(adminId)
                .orElseThrow(() -> new AuthenticationException("Utilisateur non trouvé"));

        Optional<MfaSecret> mfaSecret = mfaSecretRepository.findByAdminUserIdAndActiveTrue(adminId);

        if (mfaSecret.isEmpty()) {
            return Map.of(
                    "mfaEnabled", false,
                    "setupRequired", true
            );
        }

        long remainingBackupCodes = mfaBackupCodeRepository.countByAdminUserIdAndUsedFalse(adminId);

        return Map.of(
                "mfaEnabled", true,
                "setupRequired", false,
                "setupDate", mfaSecret.get().getCreatedAt(),
                "remainingBackupCodes", remainingBackupCodes
        );
    }

    @Transactional
    public void disableMfa(String adminId, String otpCode) {

        // Vérifier le code OTP avant de désactiver
        if (!validateOtpCode(adminId, otpCode)) {
            throw new MfaException("Code OTP invalide");
        }

        AdminUser adminUser = adminUserRepository.findById(adminId)
                .orElseThrow(() -> new AuthenticationException("Utilisateur non trouvé"));

        // Désactiver le secret MFA
        mfaSecretRepository.findByAdminUserIdAndActiveTrue(adminId)
                .ifPresent(secret -> {
                    secret.setActive(false);
                    secret.setDisabledAt(LocalDateTime.now());
                    mfaSecretRepository.save(secret);
                });

        // Supprimer les codes de récupération
        mfaBackupCodeRepository.deleteByAdminUserId(adminId);

        // Mettre à jour le statut utilisateur
        adminUser.setMfaEnabled(false);
        adminUser.setMfaSetupAt(null);
        adminUserRepository.save(adminUser);

        log.info("MFA désactivé pour admin: {}", adminUser.getEmail());
    }
}