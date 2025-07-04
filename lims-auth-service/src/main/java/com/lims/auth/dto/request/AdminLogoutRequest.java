package com.lims.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Requête de déconnexion")
public class AdminLogoutRequest {

    @NotBlank(message = "L'ID de session est obligatoire")
    @Schema(description = "ID de session à invalider",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String sessionId;
}