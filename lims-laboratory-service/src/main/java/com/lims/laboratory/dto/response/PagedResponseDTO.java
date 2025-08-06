package com.lims.laboratory.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.Builder;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * DTO générique pour les réponses paginées
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Réponse paginée générique")
public class PagedResponseDTO<T> {

    @Schema(description = "Liste des éléments de la page courante")
    private List<T> content;

    @Schema(description = "Numéro de la page courante (base 0)")
    private int page;

    @Schema(description = "Taille de la page")
    private int size;

    @Schema(description = "Nombre total d'éléments")
    private long totalElements;

    @Schema(description = "Nombre total de pages")
    private int totalPages;

    @Schema(description = "Indique si c'est la première page")
    private boolean first;

    @Schema(description = "Indique si c'est la dernière page")
    private boolean last;

    @Schema(description = "Indique s'il y a une page suivante")
    private boolean hasNext;

    @Schema(description = "Indique s'il y a une page précédente")
    private boolean hasPrevious;
}