package com.lims.referential.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * DTO de réponse pour un médicament
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Réponse contenant les informations d'un médicament")
public class MedicamentResponse {

    @Schema(description = "Identifiant unique du médicament", example = "123e4567-e89b-12d3-a456-426614174000")
    private String id;

    @Schema(description = "Code CIS du médicament", example = "CIS12345678")
    private String codeCis;

    @Schema(description = "Dénomination du médicament", example = "DOLIPRANE 500 mg, comprimé")
    private String denomination;

    @Schema(description = "Forme pharmaceutique", example = "comprimé")
    private String formePharma;

    @Schema(description = "Voies d'administration", example = "orale")
    private String voiesAdmin;

    @Schema(description = "Statut AMM", example = "Autorisation active")
    private String statutAmm;

    @Schema(description = "Type de procédure AMM", example = "Procédure nationale")
    private String typeProcedure;

    @Schema(description = "Laboratoire titulaire", example = "SANOFI AVENTIS FRANCE")
    private String laboratoireTitulaire;

    @Schema(description = "Laboratoire exploitant", example = "SANOFI AVENTIS FRANCE")
    private String laboratoireExploitant;

    @Schema(description = "Date AMM", example = "1985-07-25T00:00:00")
    private LocalDateTime dateAmm;

    @Schema(description = "Statut BdM (Base de données publique des médicaments)", example = "Commercialisé")
    private String statutBdm;

    @Schema(description = "Numéro autorisation européenne", example = "EU/1/15/1234/001")
    private String numeroAutorisationEuropeenne;

    @Schema(description = "Titulaires AMM", example = "SANOFI AVENTIS FRANCE")
    private String titulairesAmm;

    @Schema(description = "Surveillance renforcée", example = "false")
    private Boolean surveillanceRenforcee;

    @Schema(description = "Prix de vente public", example = "2.18")
    private BigDecimal prixVente;

    @Schema(description = "Taux de remboursement", example = "65")
    private Integer tauxRemboursement;

    @Schema(description = "Indique si le médicament est actif", example = "true")
    private Boolean actif;

    @Schema(description = "Date de création de l'enregistrement")
    private LocalDateTime dateCreation;

    @Schema(description = "Date de dernière modification")
    private LocalDateTime dateModification;

    @Schema(description = "Utilisateur ayant créé l'enregistrement")
    private String creePar;

    @Schema(description = "Utilisateur ayant modifié l'enregistrement")
    private String modifiePar;
}