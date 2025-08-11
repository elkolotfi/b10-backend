package com.lims.laboratory.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Critères de recherche pour les analyses")
public class AnalyseSearchDTO {

    @Schema(description = "Filtrer par laboratoire", example = "123e4567-e89b-12d3-a456-426614174000")
    private UUID laboratoireId;

    @Schema(description = "Filtrer par examen", example = "123e4567-e89b-12d3-a456-426614174001")
    private UUID laboratoireExamenId;

    @Schema(description = "Recherche textuelle dans le nom de l'analyse", example = "hémoglobine")
    @Size(max = 100, message = "Le terme de recherche ne peut dépasser 100 caractères")
    private String nomAnalyse;

    @Schema(description = "Recherche par code d'analyse", example = "HBA1C")
    @Size(max = 50, message = "Le code d'analyse ne peut dépasser 50 caractères")
    private String codeAnalyse;

    @Schema(description = "Filtrer par statut actif", example = "true")
    private Boolean analyseActive;

    @Schema(description = "Filtrer par sous-traitance", example = "false")
    private Boolean sousTraite;

    @Schema(description = "Recherche par technique", example = "HPLC")
    @Size(max = 100, message = "La technique ne peut dépasser 100 caractères")
    private String technique;

    @Schema(description = "Recherche par automate", example = "Cobas")
    @Size(max = 100, message = "L'automate ne peut dépasser 100 caractères")
    private String automate;
}