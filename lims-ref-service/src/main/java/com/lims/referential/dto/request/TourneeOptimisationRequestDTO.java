package com.lims.referential.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalTime;
import java.util.List;

@Data
@Builder
public class TourneeOptimisationRequestDTO {

    @NotNull(message = "Le point de départ est obligatoire")
    @Valid
    private PointVisiteRequestDTO pointDepart;

    @NotNull(message = "La liste des points de visite est obligatoire")
    @Size(min = 1, message = "Au moins un point de visite est requis")
    @Valid
    private List<PointVisiteRequestDTO> pointsVisite;

    private LocalTime heureDepart;

    @Builder.Default
    private String optimiserPour = "DISTANCE"; // DISTANCE, TEMPS, COUT

    @Builder.Default
    private Integer vitesseMoyenneKmH = 50;

    @Builder.Default
    private Boolean retourAuDepart = true;

    @Data
    @Builder
    public static class PointVisiteRequestDTO {
        @NotNull(message = "La latitude est obligatoire")
        private BigDecimal latitude;

        @NotNull(message = "La longitude est obligatoire")
        private BigDecimal longitude;

        @Size(max = 255, message = "L'adresse ne peut pas dépasser 255 caractères")
        private String adresse;

        @Builder.Default
        private Integer dureeVisite = 15; // en minutes

        @Builder.Default
        private Integer priorite = 1; // 1=normale, 2=prioritaire, 3=urgente

        private String commentaire;
    }
}