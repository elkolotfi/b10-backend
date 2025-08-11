package com.lims.laboratory.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Informations d'une analyse laboratoire")
public class AnalyseResponseDTO {

    @Schema(description = "Identifiant unique de l'analyse")
    private UUID id;

    @Schema(description = "Identifiant du laboratoire")
    private UUID laboratoireId;

    @Schema(description = "Identifiant de l'examen laboratoire")
    private UUID laboratoireExamenId;

    @Schema(description = "Identifiant de l'analyse référentiel")
    private UUID analyseReferentielId;

    @Schema(description = "Nom personnalisé de l'analyse")
    private String nomAnalyseLabo;

    @Schema(description = "Code interne de l'analyse")
    private String codeAnalyseLabo;

    @Schema(description = "Technique analytique utilisée")
    private String techniqueUtilisee;

    @Schema(description = "Automate/équipement utilisé")
    private String automateUtilise;

    @Schema(description = "Coefficient NABM")
    private String prixCoefficient;

    @Schema(description = "Prix de l'analyse")
    private BigDecimal prixAnalyse;

    @Schema(description = "Valeurs normales spécifiques")
    private String valeursNormalesLabo;

    @Schema(description = "Statut actif de l'analyse")
    private Boolean analyseActive;

    @Schema(description = "Analyse sous-traitée")
    private Boolean sousTraite;

    @Schema(description = "ID du laboratoire sous-traitant")
    private UUID laboratoireSousTraitantId;

    @Schema(description = "Commentaires techniques")
    private String commentairesTechnique;

    @Schema(description = "Date de création")
    private LocalDateTime createdAt;

    @Schema(description = "Date de dernière modification")
    private LocalDateTime updatedAt;

    // Informations du laboratoire (dénormalisées pour l'affichage)
    @Schema(description = "Nom du laboratoire")
    private String nomLaboratoire;

    // Informations de l'examen (dénormalisées pour l'affichage)
    @Schema(description = "Nom de l'examen")
    private String nomExamen;

    // Informations du laboratoire sous-traitant (dénormalisées pour l'affichage)
    @Schema(description = "Nom du laboratoire sous-traitant")
    private String nomLaboratoireSousTraitant;
}