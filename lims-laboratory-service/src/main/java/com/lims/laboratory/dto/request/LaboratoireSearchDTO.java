package com.lims.laboratory.dto.request;

import com.lims.laboratory.entity.Laboratoire.TypeLaboratoire;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.Builder;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

/**
 * DTO pour la recherche de laboratoires
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Critères de recherche pour les laboratoires")
public class LaboratoireSearchDTO {

    @Schema(description = "Recherche textuelle dans nom commercial, nom légal, code")
    private String searchTerm;

    @Schema(description = "Filtrer par type de laboratoire")
    private TypeLaboratoire typeLaboratoire;

    @Schema(description = "Filtrer par statut actif", defaultValue = "true")
    private Boolean actif;

    @Schema(description = "Filtrer par numéro SIRET")
    private String siret;

    @Schema(description = "Filtrer par numéro FINESS")
    private String numeroFiness;
}