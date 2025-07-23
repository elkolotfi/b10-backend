package com.lims.referential.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class MutuelleRequestDTO {

    @NotBlank(message = "Le nom est obligatoire")
    @Size(max = 255, message = "Le nom ne peut pas dépasser 255 caractères")
    private String nom;

    @Size(max = 255, message = "Le nom commercial ne peut pas dépasser 255 caractères")
    private String nomCommercial;

    @Size(max = 14, message = "Le SIRET ne peut pas dépasser 14 caractères")
    private String siret;

    // Classification
    @Size(max = 50, message = "Le type d'organisme ne peut pas dépasser 50 caractères")
    private String typeOrganisme; // cpam, mutuelle, assurance, cmuc

    @Size(max = 20, message = "Le code organisme ne peut pas dépasser 20 caractères")
    private String codeOrganisme;

    @Size(max = 100, message = "Le régime de rattachement ne peut pas dépasser 100 caractères")
    private String regimeRattachement;

    // Coordonnées
    @Valid
    private AdresseMutuelleRequestDTO adresse;

    // Contact
    @Valid
    private ContactMutuelleRequestDTO contact;

    // Informations de prise en charge
    @Valid
    private PriseEnChargeRequestDTO priseEnCharge;

    // Facturation
    @Valid
    private FacturationRequestDTO facturation;

    // Conventions spéciales
    private List<String> conventionsSpeciales;

    @Builder.Default
    private Boolean actif = true;

    @Data
    @Builder
    public static class AdresseMutuelleRequestDTO {
        @Size(max = 255)
        private String ligne1;

        @Size(max = 255)
        private String ligne2;

        @Size(max = 10)
        private String codePostal;

        @Size(max = 100)
        private String ville;

        @Size(max = 100)
        private String departement;

        @Size(max = 100)
        private String region;
    }

    @Data
    @Builder
    public static class ContactMutuelleRequestDTO {
        private String telephone;
        private String fax;

        @Email(message = "Format d'email invalide")
        @Size(max = 255)
        private String email;

        @Size(max = 255)
        private String siteWeb;
    }

    @Data
    @Builder
    public static class PriseEnChargeRequestDTO {
        @Builder.Default
        private BigDecimal tauxBaseRemboursement = new BigDecimal("70.00");

        private BigDecimal plafondAnnuelEuro;

        @Builder.Default
        private BigDecimal franchiseEuro = BigDecimal.ZERO;

        private List<AnalyseCouvertureRequestDTO> analysesCouvertes;
        private List<String> analysesExclues;
    }

    @Data
    @Builder
    public static class FacturationRequestDTO {
        private Map<String, Object> codesFacturation;

        @Builder.Default
        private Integer delaiPaiementJours = 30;

        @Size(max = 50)
        private String modeTransmission; // noemie, edifact, papier
    }

    @Data
    @Builder
    public static class AnalyseCouvertureRequestDTO {
        private String codeNabm;
        private BigDecimal tauxRemboursement;
        private BigDecimal plafond;
        private String conditions;
    }
}