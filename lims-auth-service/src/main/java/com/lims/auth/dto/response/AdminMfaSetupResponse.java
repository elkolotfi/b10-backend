package com.lims.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import com.fasterxml.jackson.annotation.JsonInclude;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Réponse de setup MFA")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AdminMfaSetupResponse {

    @Schema(description = "Succès de la génération")
    private boolean success;

    @Schema(description = "Image QR Code encodée en Base64")
    private String qrCodeImage;

    @Schema(description = "URL du QR Code")
    private String qrCodeUrl;

    @Schema(description = "Clé secrète (pour debug uniquement)")
    private String secretKey;

    @Schema(description = "Issuer du TOTP")
    private String issuer;

    @Schema(description = "Message d'erreur")
    private String errorMessage;

    public static AdminMfaSetupResponse success(String qrCodeImage, String qrCodeUrl,
                                                String secretKey, String issuer) {
        return AdminMfaSetupResponse.builder()
                .success(true)
                .qrCodeImage(qrCodeImage)
                .qrCodeUrl(qrCodeUrl)
                .secretKey(secretKey)
                .issuer(issuer)
                .build();
    }

    public static AdminMfaSetupResponse failed(String errorMessage) {
        return AdminMfaSetupResponse.builder()
                .success(false)
                .errorMessage(errorMessage)
                .build();
    }
}