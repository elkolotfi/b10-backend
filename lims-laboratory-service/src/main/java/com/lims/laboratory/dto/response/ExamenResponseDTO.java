package com.lims.laboratory.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExamenResponseDTO {

    private UUID id;
    private UUID laboratoireId;
    private String laboratoireNom;
    private UUID examenReferentielId;
    private String nomExamenLabo;
    private Boolean examenActif;
    private Boolean examenRealiseInternement;
    private String delaiRenduHabituel;
    private String delaiRenduUrgent;
    private String conditionsParticulieres;

    // Statistiques rapides
    private Integer nombreAnalyses;
    private Integer nombrePrelevements;
    private Integer nombreTarifs;

    // Métadonnées
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}