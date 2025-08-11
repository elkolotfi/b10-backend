package com.lims.laboratory.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Données pour créer ou modifier une analyse laboratoire")
public class AnalyseRequestDTO {

    @Schema(description = "ID du laboratoire", example = "123e4567-e89b-12d3-a456-426614174000")
    @NotNull(message = "L'identifiant du laboratoire est obligatoire")
    private UUID laboratoireId;

    @Schema(description = "ID de l'examen laboratoire parent", example = "123e4567-e89b-12d3-a456-426614174001")
    @NotNull(message = "L'identifiant de l'examen laboratoire est obligatoire")
    private UUID laboratoireExamenId;

    @Schema(description = "ID de l'analyse dans le référentiel", example = "123e4567-e89b-12d3-a456-426614174002")
    @NotNull(message = "L'identifiant de l'analyse référentiel est obligatoire")
    private UUID analyseReferentielId;

    @Schema(description = "Nom personnalisé de l'analyse par le laboratoire", example = "Hémoglobine A1c - Méthode HPLC")
    @Size(max = 500, message = "Le nom de l'analyse ne peut dépasser 500 caractères")
    private String nomAnalyseLabo;

    @Schema(description = "Code interne de l'analyse pour le laboratoire", example = "HBA1C_HPLC")
    @Size(max = 100, message = "Le code de l'analyse ne peut dépasser 100 caractères")
    private String codeAnalyseLabo;

    @Schema(description = "Technique analytique utilisée", example = "Chromatographie liquide haute performance")
    @Size(max = 200, message = "La technique utilisée ne peut dépasser 200 caractères")
    private String techniqueUtilisee;

    @Schema(description = "Automate/équipement utilisé", example = "Cobas c111 - Roche")
    @Size(max = 200, message = "L'automate utilisé ne peut dépasser 200 caractères")
    private String automateUtilise;

    @Schema(description = "Coefficient NABM pour la tarification", example = "B25")
    @Size(max = 10, message = "Le coefficient prix ne peut dépasser 10 caractères")
    private String prixCoefficient;

    @Schema(description = "Prix de l'analyse", example = "15.50")
    @DecimalMin(value = "0.0", inclusive = true, message = "Le prix doit être positif ou nul")
    private BigDecimal prixAnalyse;

    @Schema(description = "Valeurs normales spécifiques au laboratoire", example = "< 5.7% (normal), 5.7-6.4% (pré-diabète), ≥ 6.5% (diabète)")
    private String valeursNormalesLabo;

    @Schema(description = "L'analyse est-elle active", example = "true")
    private Boolean analyseActive = true;

    @Schema(description = "L'analyse est-elle sous-traitée", example = "false")
    private Boolean sousTraite = false;

    @Schema(description = "ID du laboratoire sous-traitant si applicable", example = "123e4567-e89b-12d3-a456-426614174003")
    private UUID laboratoireSousTraitantId;

    @Schema(description = "Commentaires techniques du laboratoire")
    private String commentairesTechnique;
}