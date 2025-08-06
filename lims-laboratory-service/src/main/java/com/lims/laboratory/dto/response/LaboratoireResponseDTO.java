package com.lims.laboratory.dto.response;

import com.lims.laboratory.entity.Laboratoire.TypeLaboratoire;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.Builder;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

/**
 * DTO de réponse pour un laboratoire
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Informations complètes d'un laboratoire")
public class LaboratoireResponseDTO {

    @Schema(description = "Identifiant unique du laboratoire")
    private UUID id;

    @Schema(description = "Nom commercial du laboratoire")
    private String nomCommercial;

    @Schema(description = "Raison sociale du laboratoire")
    private String nomLegal;

    @Schema(description = "Nom d'usage du laboratoire")
    private String nomLaboratoire;

    @Schema(description = "Code interne du laboratoire")
    private String codeLaboratoire;

    @Schema(description = "Description générale du laboratoire")
    private String description;

    @Schema(description = "Numéro SIRET")
    private String siret;

    @Schema(description = "Identifiant FINESS")
    private String numeroFiness;

    @Schema(description = "Type de laboratoire")
    private TypeLaboratoire typeLaboratoire;

    @Schema(description = "Adresse complète du laboratoire")
    private String adresse;

    @Schema(description = "Informations de contact")
    private String contact;

    @Schema(description = "Statut actif du laboratoire")
    private Boolean actif;

    @Schema(description = "Date de création")
    private Instant createdAt;

    @Schema(description = "Date de dernière modification")
    private Instant updatedAt;
}