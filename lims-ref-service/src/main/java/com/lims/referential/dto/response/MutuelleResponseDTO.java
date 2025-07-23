package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Data
@Builder
public class MutuelleResponseDTO {

    private UUID id;
    private String nom;
    private String nomCommercial;
    private String siret;

    // Classification
    private String typeOrganisme;
    private String codeOrganisme;
    private String regimeRattachement;

    // Coordonnées
    private AdresseMutuelleResponseDTO adresse;

    // Contact
    private ContactMutuelleResponseDTO contact;

    // Informations de prise en charge
    private PriseEnChargeResponseDTO priseEnCharge;

    // Facturation
    private FacturationResponseDTO facturation;

    // Conventions spéciales
    private List<String> conventionsSpeciales;
    private Boolean actif;

    // Métadonnées
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Integer version;

    @Data
    @Builder
    public static class AdresseMutuelleResponseDTO {
        private String ligne1;
        private String ligne2;
        private String codePostal;
        private String ville;
        private String departement;
        private String region;
    }

    @Data
    @Builder
    public static class ContactMutuelleResponseDTO {
        private String telephone;
        private String fax;
        private String email;
        private String siteWeb;
    }

    @Data
    @Builder
    public static class PriseEnChargeResponseDTO {
        private BigDecimal tauxBaseRemboursement;
        private BigDecimal plafondAnnuelEuro;
        private BigDecimal franchiseEuro;
        private List<AnalyseCouvertureResponseDTO> analysesCouvertes;
        private List<String> analysesExclues;
    }

    @Data
    @Builder
    public static class FacturationResponseDTO {
        private Map<String, Object> codesFacturation;
        private Integer delaiPaiementJours;
        private String modeTransmission;
    }

    @Data
    @Builder
    public static class AnalyseCouvertureResponseDTO {
        private String codeNabm;
        private BigDecimal tauxRemboursement;
        private BigDecimal plafond;
        private String conditions;
    }
}