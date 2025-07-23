package com.lims.referential.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@Schema(description = "Réponse contenant les informations d'un laboratoire")
public class LaboratoireResponseDTO {

    @Schema(description = "Identifiant unique du laboratoire")
    private String id;

    @Schema(description = "Nom du laboratoire")
    private String nom;

    @Schema(description = "Description du laboratoire")
    private String description;

    @Schema(description = "Adresse complète")
    private String adresse;

    @Schema(description = "Ville")
    private String ville;

    @Schema(description = "Code postal")
    private String codePostal;

    @Schema(description = "Pays")
    private String pays;

    @Schema(description = "Informations de contact")
    private ContactResponseDTO contact;

    @Schema(description = "Informations pratiques")
    private InformationsPratiquesResponseDTO informationsPratiques;

    @Schema(description = "Capacités techniques")
    private CapacitesTechniquesResponseDTO capacitesTechniques;

    @Schema(description = "Statut actif du laboratoire")
    private Boolean actif;

    @Schema(description = "Date de création")
    private LocalDateTime dateCreation;

    @Schema(description = "Date de modification")
    private LocalDateTime dateModification;

    @Schema(description = "Créé par")
    private String creePar;

    @Schema(description = "Modifié par")
    private String modifiePar;

    // ============================================
    // DTOs DE RÉPONSE IMBRIQUÉS
    // ============================================

    @Data
    @Builder
    public static class ContactResponseDTO {
        private String telephone;
        private String fax;
        private String email;
        private String siteWeb;
    }

    @Data
    @Builder
    public static class InformationsPratiquesResponseDTO {
        private String horairesOuverture;
        private Boolean parkingDisponible;
        private Boolean accesHandicapes;
        private String transportPublic;
    }

    @Data
    @Builder
    public static class CapacitesTechniquesResponseDTO {
        private List<String> analysesDisponibles;
        private List<String> specialitesTechniques;
        private List<String> equipementsSpeciaux;
    }
}