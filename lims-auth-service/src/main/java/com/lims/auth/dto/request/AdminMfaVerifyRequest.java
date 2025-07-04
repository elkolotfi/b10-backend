package com.lims.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Requête de vérification MFA")
public class AdminMfaVerifyRequest {

    @NotBlank(message = "Le code OTP est obligatoire")
    @Pattern(regexp = "^[0-9]{6}$", message = "Le code OTP doit contenir exactement 6 chiffres")
    @Schema(description = "Code OTP Google Authenticator",
            example = "123456",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String otpCode;

    @NotBlank(message = "Le token de setup est obligatoire")
    @Schema(description = "Token de setup MFA temporaire",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String setupToken;
}