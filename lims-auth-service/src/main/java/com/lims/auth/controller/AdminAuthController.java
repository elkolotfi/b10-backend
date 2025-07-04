package com.lims.auth.controller;

import com.lims.auth.dto.request.AdminLoginRequest;
import com.lims.auth.dto.request.AdminMfaSetupRequest;
import com.lims.auth.dto.request.AdminMfaVerifyRequest;
import com.lims.auth.dto.request.AdminRefreshTokenRequest;
import com.lims.auth.dto.request.AdminLogoutRequest;
import com.lims.auth.dto.response.AdminLoginResponse;
import com.lims.auth.dto.response.AdminMfaSetupResponse;
import com.lims.auth.dto.response.AdminTokenResponse;
import com.lims.auth.dto.response.AdminUserResponse;
import com.lims.auth.service.AdminAuthenticationService;
import com.lims.auth.service.AdminMfaService;
import com.lims.auth.service.AdminTokenService;
import com.lims.auth.exception.AuthenticationException;
import com.lims.auth.exception.MfaException;
import com.lims.auth.exception.RateLimitException;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth/admin")
@Tag(name = "Admin Authentication", description = "Endpoints d'authentification pour les administrateurs LIMS")
@RequiredArgsConstructor
@Slf4j
@Validated
public class AdminAuthController {

    private final AdminAuthenticationService adminAuthService;
    private final AdminMfaService adminMfaService;
    private final AdminTokenService adminTokenService;

    @Operation(summary = "Connexion administrateur", description = "Authentifie un administrateur avec email/mot de passe et MFA obligatoire. " + "Premier login nécessite setup MFA avec Google Authenticator.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Connexion réussie"), @ApiResponse(responseCode = "401", description = "Identifiants invalides"), @ApiResponse(responseCode = "429", description = "Trop de tentatives - Rate limiting actif"), @ApiResponse(responseCode = "423", description = "Compte temporairement verrouillé")})
    @PostMapping("/login")
    public ResponseEntity<AdminLoginResponse> login(@Valid @RequestBody AdminLoginRequest request, HttpServletRequest httpRequest) {

        String clientIp = getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        log.info("Tentative de connexion admin - Email: {}, IP: {}", request.getEmail(), clientIp);

        try {
            AdminLoginResponse response = adminAuthService.authenticate(request, clientIp, userAgent);

            if (response.isRequiresMfaSetup()) {
                log.info("Premier login admin détecté - Setup MFA requis - Email: {}", request.getEmail());
                return ResponseEntity.ok(response);
            }

            if (response.isSuccess()) {
                log.info("Connexion admin réussie - Email: {}, SessionId: {}", request.getEmail(), response.getSessionId());
                return ResponseEntity.ok(response);
            }

            log.warn("Échec connexion admin - Email: {}, Raison: {}", request.getEmail(), response.getErrorMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);

        } catch (RateLimitException e) {
            log.warn("Rate limiting actif pour admin - Email: {}, IP: {}", request.getEmail(), clientIp);
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(AdminLoginResponse.rateLimitExceeded(e.getMessage()));

        } catch (AuthenticationException e) {
            log.error("Erreur authentification admin - Email: {}, Erreur: {}", request.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(AdminLoginResponse.failed(e.getMessage()));

        } catch (Exception e) {
            log.error("Erreur inattendue lors connexion admin - Email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(AdminLoginResponse.failed("Erreur technique temporaire"));
        }
    }

    @Operation(summary = "Setup MFA - Génération QR Code", description = "Génère un QR Code Google Authenticator pour le setup initial MFA. " + "Utilise un token temporaire de setup.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "QR Code généré avec succès"), @ApiResponse(responseCode = "400", description = "Token setup invalide ou expiré"), @ApiResponse(responseCode = "401", description = "Non autorisé")})
    @GetMapping("/mfa/setup")
    public ResponseEntity<AdminMfaSetupResponse> setupMfa(@Parameter(description = "Token de setup MFA temporaire", required = true) @RequestParam("setupToken") String setupToken) {

        log.info("Demande setup MFA - Token: {}", setupToken.substring(0, 8) + "...");

        try {
            AdminMfaSetupResponse response = adminMfaService.generateMfaSetup(setupToken);

            log.info("QR Code MFA généré - Token: {}", setupToken.substring(0, 8) + "...");
            return ResponseEntity.ok(response);

        } catch (MfaException e) {
            log.error("Erreur génération QR Code MFA - Token: {}, Erreur: {}", setupToken.substring(0, 8) + "...", e.getMessage());
            return ResponseEntity.badRequest().body(AdminMfaSetupResponse.failed(e.getMessage()));
        }
    }

    @Operation(summary = "Vérification Setup MFA", description = "Valide le premier code OTP généré par Google Authenticator et finalise le setup MFA. " + "Génère les codes de récupération et connecte automatiquement l'utilisateur.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Setup MFA complété avec succès"), @ApiResponse(responseCode = "400", description = "Code OTP invalide"), @ApiResponse(responseCode = "401", description = "Token setup invalide")})
    @PostMapping("/mfa/setup/verify")
    public ResponseEntity<AdminLoginResponse> verifyMfaSetup(@Valid @RequestBody AdminMfaVerifyRequest request, HttpServletRequest httpRequest) {

        String clientIp = getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        log.info("Vérification setup MFA - Token: {}", request.getSetupToken().substring(0, 8) + "...");

        try {
            AdminLoginResponse response = adminMfaService.verifyMfaSetup(request, clientIp, userAgent);

            if (response.isSuccess()) {
                log.info("Setup MFA complété avec succès - SessionId: {}", response.getSessionId());
                return ResponseEntity.ok(response);
            }

            log.warn("Échec vérification setup MFA - Raison: {}", response.getErrorMessage());
            return ResponseEntity.badRequest().body(response);

        } catch (MfaException e) {
            log.error("Erreur vérification setup MFA - Erreur: {}", e.getMessage());
            return ResponseEntity.badRequest().body(AdminLoginResponse.failed(e.getMessage()));
        }
    }

    @Operation(summary = "Rafraîchissement token", description = "Génère un nouveau token d'accès à partir du refresh token valide.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Token rafraîchi avec succès"), @ApiResponse(responseCode = "401", description = "Refresh token invalide ou expiré")})
    @PostMapping("/refresh")
    public ResponseEntity<AdminTokenResponse> refreshToken(@Valid @RequestBody AdminRefreshTokenRequest request, HttpServletRequest httpRequest) {

        String clientIp = getClientIp(httpRequest);

        log.debug("Demande rafraîchissement token - IP: {}", clientIp);

        try {
            AdminTokenResponse response = adminTokenService.refreshToken(request.getRefreshToken(), clientIp);

            log.debug("Token rafraîchi avec succès");
            return ResponseEntity.ok(response);

        } catch (AuthenticationException e) {
            log.warn("Échec rafraîchissement token - Erreur: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(AdminTokenResponse.failed(e.getMessage()));
        }
    }

    @Operation(summary = "Déconnexion administrateur", description = "Déconnecte l'administrateur, invalide la session et révoque les tokens.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Déconnexion réussie"), @ApiResponse(responseCode = "401", description = "Non autorisé")})
    @PostMapping("/logout")
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<Map<String, Object>> logout(@Valid @RequestBody AdminLogoutRequest request, @AuthenticationPrincipal Jwt jwt, HttpServletRequest httpRequest) {

        String adminId = jwt.getSubject();
        String clientIp = getClientIp(httpRequest);

        log.info("Déconnexion admin - AdminId: {}, SessionId: {}", adminId, request.getSessionId());

        try {
            adminAuthService.logout(adminId, request.getSessionId(), clientIp);

            log.info("Déconnexion admin réussie - AdminId: {}", adminId);
            return ResponseEntity.ok(Map.of("success", true, "message", "Déconnexion réussie"));

        } catch (Exception e) {
            log.error("Erreur déconnexion admin - AdminId: {}", adminId, e);
            return ResponseEntity.ok(Map.of("success", false, "message", "Erreur lors de la déconnexion"));
        }
    }

    @Operation(summary = "Informations administrateur connecté", description = "Retourne les informations de l'administrateur actuellement connecté.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Informations récupérées"), @ApiResponse(responseCode = "401", description = "Non autorisé")})
    @GetMapping("/me")
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<AdminUserResponse> getCurrentAdmin(@AuthenticationPrincipal Jwt jwt) {

        String adminId = jwt.getSubject();

        log.debug("Récupération informations admin - AdminId: {}", adminId);

        try {
            AdminUserResponse response = adminAuthService.getCurrentAdmin(adminId);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Erreur récupération informations admin - AdminId: {}", adminId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @Operation(summary = "Permissions administrateur", description = "Retourne les permissions de l'administrateur connecté.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Permissions récupérées"), @ApiResponse(responseCode = "401", description = "Non autorisé")})
    @GetMapping("/permissions")
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<Map<String, Object>> getAdminPermissions(@AuthenticationPrincipal Jwt jwt) {

        String adminId = jwt.getSubject();

        log.debug("Récupération permissions admin - AdminId: {}", adminId);

        try {
            Map<String, Object> permissions = adminAuthService.getAdminPermissions(adminId);
            return ResponseEntity.ok(permissions);

        } catch (Exception e) {
            log.error("Erreur récupération permissions admin - AdminId: {}", adminId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @Operation(summary = "Statut de session", description = "Retourne le statut de la session courante de l'administrateur.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Statut de session récupéré"), @ApiResponse(responseCode = "401", description = "Non autorisé")})
    @GetMapping("/session/status")
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<Map<String, Object>> getSessionStatus(@AuthenticationPrincipal Jwt jwt) {

        String adminId = jwt.getSubject();

        log.debug("Récupération statut session admin - AdminId: {}", adminId);

        try {
            Map<String, Object> sessionStatus = adminTokenService.getSessionStatus(adminId);
            return ResponseEntity.ok(sessionStatus);

        } catch (Exception e) {
            log.error("Erreur récupération statut session admin - AdminId: {}", adminId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Extraction de l'adresse IP du client
     */
    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }
}