package com.lims.referential.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * DTO pour mettre à jour un médicament existant
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Données pour mettre à jour un médicament existant")
public class UpdateMedicamentRequest {

    @Size(max = 500, message = "La dénomination ne peut pas dépasser 500 caractères")
    @Schema(description = "Dénomination du médicament", example = "DOLIPRANE 500 mg, comprimé")
    private String denomination;

    @Size(max = 200, message = "La forme pharmaceutique ne peut pas dépasser 200 caractères")
    @Schema(description = "Forme pharmaceutique", example = "comprimé")
    private String formePharma;

    @Size(max = 200, message = "Les voies d'administration ne peuvent pas dépasser 200 caractères")
    @Schema(description = "Voies d'administration", example = "orale")
    private String voiesAdmin;

    @Size(max = 100, message = "Le statut AMM ne peut pas dépasser 100 caractères")
    @Schema(description = "Statut AMM", example = "Autorisation active")
    private String statutAmm;

    @Size(max = 100, message = "Le type de procédure ne peut pas dépasser 100 caractères")
    @Schema(description = "Type de procédure AMM", example = "Procédure nationale")
    private String typeProcedure;

    @Size(max = 300, message = "Le laboratoire titulaire ne peut pas dépasser 300 caractères")
    @Schema(description = "Laboratoire titulaire", example = "SANOFI AVENTIS FRANCE")
    private String laboratoireTitulaire;

    @Size(max = 300, message = "Le laboratoire exploitant ne peut pas dépasser 300 caractères")
    @Schema(description = "Laboratoire exploitant", example = "SANOFI AVENTIS FRANCE")
    private String laboratoireExploitant;

    @Schema(description = "Date AMM", example = "1985-07-25T00:00:00")
    private LocalDateTime dateAmm;

    @Size(max = 100, message = "Le statut BdM ne peut pas dépasser 100 caractères")
    @Schema(description = "Statut BdM", example = "Commercialisé")
    private String statutBdm;

    @Size(max = 100, message = "Le numéro autorisation européenne ne peut pas dépasser 100 caractères")
    @Schema(description = "Numéro autorisation européenne", example = "EU/1/15/1234/001")
    private String numeroAutorisationEuropeenne;

    @Size(max = 500, message = "Les titulaires AMM ne peuvent pas dépasser 500 caractères")
    @Schema(description = "Titulaires AMM", example = "SANOFI AVENTIS FRANCE")
    private String titulairesAmm;

    @Schema(description = "Surveillance renforcée", example = "false")
    private Boolean surveillanceRenforcee;

    @DecimalMin(value = "0.0", message = "Le prix de vente doit être positif")
    @Digits(integer = 10, fraction = 2, message = "Le prix de vente ne peut avoir plus de 2 décimales")
    @Schema(description = "Prix de vente public", example = "2.18")
    private BigDecimal prixVente;

    @Min(value = 0, message = "Le taux de remboursement doit être positif")
    @Max(value = 100, message = "Le taux de remboursement ne peut pas dépasser 100%")
    @Schema(description = "Taux de remboursement", example = "65")
    private Integer tauxRemboursement;

    @Schema(description = "Indique si le médicament est actif", example = "true")
    private Boolean actif;
}