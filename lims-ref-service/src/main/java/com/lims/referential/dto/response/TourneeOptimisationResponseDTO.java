package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;

@Data
@Builder
public class TourneeOptimisationResponseDTO {

    private List<EtapeResponseDTO> etapesOptimisees;
    private BigDecimal distanceTotaleKm;
    private Integer dureeVisitesTotaleMinutes;
    private Integer dureeTrajetTotaleMinutes;
    private LocalTime heureDepart;
    private LocalTime heureRetourEstimee;
    private String critereOptimisation;
    private LocalDateTime calculeLe;

    @Data
    @Builder
    public static class EtapeResponseDTO {
        private Integer ordre;
        private BigDecimal latitude;
        private BigDecimal longitude;
        private String adresse;
        private LocalTime heureArriveeEstimee;
        private Integer dureeVisite;
        private BigDecimal distanceDepuisPrecedent;
        private String commentaire;
    }
}