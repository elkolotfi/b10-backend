package com.lims.referential.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class LaboratoireRequestDTO {

    @NotBlank(message = "Le nom du laboratoire est obligatoire")
    @Size(max = 255, message = "Le nom ne peut pas dépasser 255 caractères")
    private String nom;

    @Size(max = 500, message = "La description ne peut pas dépasser 500 caractères")
    private String description;

    @NotBlank(message = "L'adresse est obligatoire")
    @Size(max = 500, message = "L'adresse ne peut pas dépasser 500 caractères")
    private String adresse;

    @NotBlank(message = "La ville est obligatoire")
    @Size(max = 100, message = "La ville ne peut pas dépasser 100 caractères")
    private String ville;

    @NotBlank(message = "Le code postal est obligatoire")
    @Size(max = 10, message = "Le code postal ne peut pas dépasser 10 caractères")
    private String codePostal;

    @Size(max = 100, message = "Le pays ne peut pas dépasser 100 caractères")
    private String pays;

    // Informations de contact (mappées vers les propriétés de l'entité)
    @Valid
    private ContactDTO contact;

    // Informations pratiques
    @Valid
    private InformationsPratiquesDTO informationsPratiques;

    // Capacités techniques
    @Valid
    private CapacitesTechniquesDTO capacitesTechniques;

    @Builder.Default
    private Boolean actif = true;

    // ============================================
    // DTOs IMBRIQUÉS
    // ============================================

    @Data
    @Builder
    public static class ContactDTO {
        @Size(max = 20, message = "Le téléphone ne peut pas dépasser 20 caractères")
        private String telephone;

        @Size(max = 20, message = "Le fax ne peut pas dépasser 20 caractères")
        private String fax;

        @Size(max = 255, message = "L'email ne peut pas dépasser 255 caractères")
        private String email;

        @Size(max = 255, message = "L'URL du site web ne peut pas dépasser 255 caractères")
        private String siteWeb;
    }

    @Data
    @Builder
    public static class InformationsPratiquesDTO {
        @Size(max = 500, message = "Les horaires ne peuvent pas dépasser 500 caractères")
        private String horairesOuverture;

        @Builder.Default
        private Boolean parkingDisponible = false;

        @Builder.Default
        private Boolean accesHandicapes = false;

        @Size(max = 255, message = "Les infos transport ne peuvent pas dépasser 255 caractères")
        private String transportPublic;
    }

    @Data
    @Builder
    public static class CapacitesTechniquesDTO {
        private List<String> analysesDisponibles;
        private List<String> specialitesTechniques;
        private List<String> equipementsSpeciaux;
    }
}