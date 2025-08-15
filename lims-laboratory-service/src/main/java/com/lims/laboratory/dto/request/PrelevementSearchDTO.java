package com.lims.laboratory.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.util.UUID;

/**
 * DTO pour la recherche et le filtrage des prélèvements
 */
@Data
@Schema(description = "Critères de recherche pour les prélèvements")
public class PrelevementSearchDTO {

    @Schema(description = "Identifiant du laboratoire pour filtrer", example = "123e4567-e89b-12d3-a456-426614174000")
    private UUID laboratoireId;

    @Schema(description = "Identifiant de l'examen pour filtrer", example = "123e4567-e89b-12d3-a456-426614174001")
    private UUID laboratoireExamenId;

    @Schema(description = "Code de nature de prélèvement pour filtrer", example = "SANG")
    private String naturePrelevementCode;

    @Schema(description = "Nom du prélèvement pour recherche textuelle", example = "sang")
    private String nomPrelevement;

    @Schema(description = "Type de tube pour filtrer", example = "Tube sec")
    private String typeTube;

    @Schema(description = "Couleur de tube pour filtrer", example = "Rouge")
    private String couleurTube;

    @Schema(description = "Filtrer uniquement les prélèvements obligatoires", example = "true")
    private Boolean prelevementObligatoire;
}