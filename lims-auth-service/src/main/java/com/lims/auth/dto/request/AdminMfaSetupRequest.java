package com.lims.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Requête de setup MFA")
public class AdminMfaSetupRequest {

    @NotBlank(message = "Le token de setup est obligatoire")
    @Schema(description = "Token de setup MFA temporaire",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String setupToken;
}