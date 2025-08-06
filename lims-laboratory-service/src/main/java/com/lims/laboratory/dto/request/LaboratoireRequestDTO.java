package com.lims.laboratory.dto.request;

import com.lims.laboratory.entity.Laboratoire.TypeLaboratoire;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.Builder;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

/**
 * DTO pour la création et mise à jour d'un laboratoire
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Données pour créer ou modifier un laboratoire")
public class LaboratoireRequestDTO {

    @NotBlank(message = "Le nom commercial est obligatoire")
    @Size(max = 255, message = "Le nom commercial ne peut pas dépasser 255 caractères")
    @Schema(description = "Nom commercial du laboratoire", example = "Laboratoire Central")
    private String nomCommercial;

    @NotBlank(message = "Le nom légal est obligatoire")
    @Size(max = 255, message = "Le nom légal ne peut pas dépasser 255 caractères")
    @Schema(description = "Raison sociale du laboratoire", example = "Laboratoire Central SAS")
    private String nomLegal;

    @Size(max = 500, message = "Le nom du laboratoire ne peut pas dépasser 500 caractères")
    @Schema(description = "Nom d'usage du laboratoire", example = "Labo Central - Site Principal")
    private String nomLaboratoire;

    @Size(max = 100, message = "Le code laboratoire ne peut pas dépasser 100 caractères")
    @Schema(description = "Code interne du laboratoire", example = "LAB001")
    private String codeLaboratoire;

    @Schema(description = "Description générale du laboratoire")
    private String description;

    @Pattern(regexp = "^[0-9]{14}$", message = "Le SIRET doit contenir exactement 14 chiffres")
    @Schema(description = "Numéro SIRET", example = "12345678901234")
    private String siret;

    @Size(max = 20, message = "Le numéro FINESS ne peut pas dépasser 20 caractères")
    @Schema(description = "Identifiant FINESS", example = "123456789")
    private String numeroFiness;

    @Schema(description = "Type de laboratoire", allowableValues = {"PRIVE", "HOSPITALIER", "PUBLIC", "MIXTE", "RECHERCHE"})
    private TypeLaboratoire typeLaboratoire;

    @Schema(description = "Adresse complète du laboratoire")
    private String adresse;

    @Schema(description = "Informations de contact")
    private String contact;

    @Schema(description = "Statut actif du laboratoire", defaultValue = "true")
    private Boolean actif = true;
}