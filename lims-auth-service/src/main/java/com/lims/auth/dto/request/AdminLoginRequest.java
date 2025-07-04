package com.lims.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import com.fasterxml.jackson.annotation.JsonProperty;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Requête de connexion administrateur")
public class AdminLoginRequest {

    @NotBlank(message = "L'email est obligatoire")
    @Email(message = "Format d'email invalide")
    @Size(max = 255, message = "L'email ne peut pas dépasser 255 caractères")
    @Schema(description = "Adresse email de l'administrateur", example = "admin@lims.local", requiredMode = Schema.RequiredMode.REQUIRED)
    private String email;

    @NotBlank(message = "Le mot de passe est obligatoire")
    @Size(min = 8, max = 128, message = "Le mot de passe doit contenir entre 8 et 128 caractères")
    @Schema(description = "Mot de passe", example = "SuperSecretPassword123!", requiredMode = Schema.RequiredMode.REQUIRED)
    private String password;

    @Pattern(regexp = "^[0-9]{6}$", message = "Le code OTP doit contenir exactement 6 chiffres")
    @Schema(description = "Code OTP Google Authenticator (6 chiffres)", example = "123456", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    @JsonProperty("otpCode")
    private String otpCode;

    @Schema(description = "Indicateur de connexion depuis un appareil de confiance", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private boolean rememberDevice = false;
}