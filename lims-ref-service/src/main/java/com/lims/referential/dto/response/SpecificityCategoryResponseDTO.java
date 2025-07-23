package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
public class SpecificityCategoryResponseDTO {

    private String id;
    private String nom;
    private String description;
    private String couleur;
    private String icone;
    private Integer ordreAffichage;
    private Boolean actif;

    // Métadonnées
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Spécificités associées (optionnel)
    private List<PatientSpecificityResponseDTO> specificities;
}