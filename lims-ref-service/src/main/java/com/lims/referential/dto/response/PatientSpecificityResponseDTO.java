package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class PatientSpecificityResponseDTO {

    private UUID id;
    private String titre;
    private String description;
    private String categoryId;

    // Catégorie associée
    private SpecificityCategoryResponseDTO category;

    // Niveau d'alerte
    private String niveauAlerte;
    private String icone;

    // Mots-clés pour recherche
    private List<String> motsCles;

    // Instructions associées
    private String instructionsPreleveur;
    private String instructionsTechnique;
    private String instructionsAdministrative;

    // Contraintes pré-analytiques
    private List<String> impactPrelevements;
    private List<String> analysesContreIndiquees;
    private List<String> analysesModifiees;

    // Priorité et temps
    private Integer prioritePreleveur;
    private Integer tempsSupplementaireMinutes;
    private Boolean actif;

    // Métadonnées
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Integer version;
}