package com.lims.laboratory.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * DTO de réponse pour un prélèvement
 */
@Data
@Schema(description = "Informations d'un prélèvement de laboratoire")
public class PrelevementResponseDTO {

    @Schema(description = "Identifiant unique du prélèvement", example = "123e4567-e89b-12d3-a456-426614174002")
    private UUID id;

    @Schema(description = "Identifiant du laboratoire", example = "123e4567-e89b-12d3-a456-426614174000")
    private UUID laboratoireId;

    @Schema(description = "Nom du laboratoire", example = "Laboratoire ABC")
    private String nomLaboratoire;

    @Schema(description = "Identifiant de l'examen du laboratoire", example = "123e4567-e89b-12d3-a456-426614174001")
    private UUID laboratoireExamenId;

    @Schema(description = "Nom de l'examen", example = "Bilan lipidique")
    private String nomExamen;

    @Schema(description = "Code de la nature de prélèvement", example = "SANG")
    private String naturePrelevementCode;

    @Schema(description = "Nom personnalisé du prélèvement", example = "Prise de sang veineux")
    private String nomPrelevementLabo;

    @Schema(description = "Type de tube utilisé", example = "Tube sec")
    private String typeTubeLabo;

    @Schema(description = "Couleur du tube", example = "Rouge")
    private String couleurTube;

    @Schema(description = "Volume recommandé en mL", example = "5 mL")
    private String volumeRecommande;

    @Schema(description = "Instructions spécifiques", example = "Prélèvement à jeun obligatoire")
    private String instructionsPrelevement;

    @Schema(description = "Coefficient NABM", example = "P5")
    private String prixCoefficientPrelevement;

    @Schema(description = "Prix du prélèvement", example = "15.50")
    private BigDecimal prixPrelevement;

    @Schema(description = "Prélèvement obligatoire", example = "true")
    private Boolean prelevementObligatoire;

    @Schema(description = "Ordre de prélèvement", example = "1")
    private Integer ordrePrelevement;

    @Schema(description = "Date de création", example = "2024-01-15T10:30:00")
    private LocalDateTime createdAt;

    @Schema(description = "Date de dernière modification", example = "2024-01-15T14:45:00")
    private LocalDateTime updatedAt;
}