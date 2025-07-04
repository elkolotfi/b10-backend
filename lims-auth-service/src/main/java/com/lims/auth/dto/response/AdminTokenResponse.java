package com.lims.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Réponse de token")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AdminTokenResponse {

    @Schema(description = "Succès de l'opération")
    private boolean success;

    @Schema(description = "Nouveau token d'accès")
    private String accessToken;

    @Schema(description = "Nouveau token de rafraîchissement")
    private String refreshToken;

    @Schema(description = "Durée de validité en secondes")
    private Long expiresIn;

    @Schema(description = "Type de token")
    private String tokenType = "Bearer";

    @Schema(description = "Message d'erreur")
    private String errorMessage;

    @Schema(description = "Timestamp de la réponse")
    private LocalDateTime timestamp;

    public static AdminTokenResponse success(String accessToken, String refreshToken, Long expiresIn) {
        return AdminTokenResponse.builder()
                .success(true)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(expiresIn)
                .timestamp(LocalDateTime.now())
                .build();
    }

    public static AdminTokenResponse failed(String errorMessage) {
        return AdminTokenResponse.builder()
                .success(false)
                .errorMessage(errorMessage)
                .timestamp(LocalDateTime.now())
                .build();
    }
}