package com.lims.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Réponse de connexion administrateur")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AdminLoginResponse {

    @Schema(description = "Succès de la connexion")
    private boolean success;

    @Schema(description = "Setup MFA requis pour premier login")
    @JsonProperty("requiresMfaSetup")
    private boolean requiresMfaSetup;

    @Schema(description = "Token temporaire pour setup MFA")
    private String setupToken;

    @Schema(description = "Token d'accès JWT")
    private String accessToken;

    @Schema(description = "Token de rafraîchissement")
    private String refreshToken;

    @Schema(description = "ID de session")
    private String sessionId;

    @Schema(description = "Informations utilisateur")
    private AdminUserInfo user;

    @Schema(description = "Codes de récupération MFA (uniquement lors du setup)")
    private List<String> backupCodes;

    @Schema(description = "Message d'erreur")
    private String errorMessage;

    @Schema(description = "Code d'erreur")
    private String errorCode;

    @Schema(description = "Durée de validité du token en secondes")
    private Long expiresIn;

    @Schema(description = "Timestamp de la réponse")
    private LocalDateTime timestamp;

    // Méthodes utilitaires statiques
    public static AdminLoginResponse success(String accessToken, String refreshToken,
                                             String sessionId, AdminUserInfo user) {
        return AdminLoginResponse.builder()
                .success(true)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .sessionId(sessionId)
                .user(user)
                .timestamp(LocalDateTime.now())
                .build();
    }

    public static AdminLoginResponse mfaSetupRequired(String setupToken) {
        return AdminLoginResponse.builder()
                .success(false)
                .requiresMfaSetup(true)
                .setupToken(setupToken)
                .timestamp(LocalDateTime.now())
                .build();
    }

    public static AdminLoginResponse failed(String errorMessage) {
        return AdminLoginResponse.builder()
                .success(false)
                .errorMessage(errorMessage)
                .timestamp(LocalDateTime.now())
                .build();
    }

    public static AdminLoginResponse rateLimitExceeded(String message) {
        return AdminLoginResponse.builder()
                .success(false)
                .errorMessage(message)
                .errorCode("RATE_LIMIT_EXCEEDED")
                .timestamp(LocalDateTime.now())
                .build();
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    @Schema(description = "Informations utilisateur administrateur")
    public static class AdminUserInfo {
        @Schema(description = "ID unique de l'administrateur")
        private String id;

        @Schema(description = "Adresse email")
        private String email;

        @Schema(description = "Prénom")
        private String firstName;

        @Schema(description = "Nom de famille")
        private String lastName;

        @Schema(description = "Rôle administrateur")
        private String role;

        @Schema(description = "Realm Keycloak")
        private String realm;

        @Schema(description = "Type d'utilisateur")
        private String userType;

        @Schema(description = "Permissions")
        private List<String> permissions;

        @Schema(description = "Statut MFA")
        private boolean mfaEnabled;

        @Schema(description = "Date de dernière connexion")
        private LocalDateTime lastLogin;

        @Schema(description = "Statut du compte")
        private String status;
    }
}