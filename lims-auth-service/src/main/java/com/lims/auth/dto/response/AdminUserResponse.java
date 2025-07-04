package com.lims.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Réponse utilisateur administrateur")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AdminUserResponse {

    @Schema(description = "ID unique de l'administrateur")
    private String id;

    @Schema(description = "Adresse email")
    private String email;

    @Schema(description = "Prénom")
    private String firstName;

    @Schema(description = "Nom de famille")
    private String lastName;

    @Schema(description = "Nom complet")
    private String fullName;

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

    @Schema(description = "Date de création du compte")
    private LocalDateTime createdAt;

    @Schema(description = "Date de dernière connexion")
    private LocalDateTime lastLogin;

    @Schema(description = "Adresse IP de dernière connexion")
    private String lastLoginIp;

    @Schema(description = "Statut du compte")
    private String status;

    @Schema(description = "Nombre de tentatives de connexion échouées")
    private Integer failedAttempts;

    @Schema(description = "Indicateur de verrouillage temporaire")
    private boolean temporarilyLocked;

    @Schema(description = "Date de fin de verrouillage")
    private LocalDateTime lockedUntil;
}