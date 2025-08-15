package com.lims.laboratory.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.Data;

import java.math.BigDecimal;
import java.util.UUID;

/**
 * DTO pour la création et mise à jour d'un prélèvement
 */
@Data
@Schema(description = "Données pour créer ou modifier un prélèvement de laboratoire")
public class PrelevementRequestDTO {

    @NotNull(message = "L'ID du laboratoire est obligatoire")
    @Schema(description = "Identifiant du laboratoire", example = "123e4567-e89b-12d3-a456-426614174000")
    private UUID laboratoireId;

    @NotNull(message = "L'ID de l'examen du laboratoire est obligatoire")
    @Schema(description = "Identifiant de l'examen du laboratoire", example = "123e4567-e89b-12d3-a456-426614174001")
    private UUID laboratoireExamenId;

    @NotBlank(message = "Le code de nature de prélèvement est obligatoire")
    @Size(max = 20, message = "Le code de nature de prélèvement ne peut pas dépasser 20 caractères")
    @Schema(description = "Code de la nature de prélèvement (référence vers le référentiel)", example = "SANG")
    private String naturePrelevementCode;

    @Size(max = 200, message = "Le nom du prélèvement ne peut pas dépasser 200 caractères")
    @Schema(description = "Nom personnalisé du prélèvement par le laboratoire", example = "Prise de sang veineux")
    private String nomPrelevementLabo;

    @Size(max = 100, message = "Le type de tube ne peut pas dépasser 100 caractères")
    @Schema(description = "Type de tube utilisé par le laboratoire", example = "Tube sec")
    private String typeTubeLabo;

    @Size(max = 50, message = "La couleur du tube ne peut pas dépasser 50 caractères")
    @Schema(description = "Couleur du tube", example = "Rouge")
    private String couleurTube;

    @Size(max = 50, message = "Le volume recommandé ne peut pas dépasser 50 caractères")
    @Schema(description = "Volume recommandé", example = "5 mL")
    private String volumeRecommande;

    @Schema(description = "Instructions spécifiques pour le prélèvement", example = "Prélèvement à jeun obligatoire")
    private String instructionsPrelevement;

    @Size(max = 10, message = "Le coefficient prix ne peut pas dépasser 10 caractères")
    @Schema(description = "Coefficient NABM pour le prélèvement", example = "P5")
    private String prixCoefficientPrelevement;

    @DecimalMin(value = "0.00", message = "Le prix ne peut pas être négatif")
    @Digits(integer = 8, fraction = 2, message = "Le prix doit avoir au maximum 8 chiffres avant la virgule et 2 après")
    @Schema(description = "Prix du prélèvement", example = "15.50")
    private BigDecimal prixPrelevement;

    @Schema(description = "Indique si le prélèvement est obligatoire", example = "true")
    private Boolean prelevementObligatoire = true;

    @Min(value = 1, message = "L'ordre de prélèvement doit être au minimum 1")
    @Schema(description = "Ordre de prélèvement", example = "1")
    private Integer ordrePrelevement = 1;
}