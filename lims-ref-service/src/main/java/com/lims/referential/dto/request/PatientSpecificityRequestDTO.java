package com.lims.referential.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class PatientSpecificityRequestDTO {

    @NotBlank(message = "Le titre est obligatoire")
    @Size(max = 255, message = "Le titre ne peut pas dépasser 255 caractères")
    private String titre;

    private String description;

    @Size(max = 50, message = "L'ID de catégorie ne peut pas dépasser 50 caractères")
    private String categoryId;

    // Niveau d'alerte
    @NotBlank(message = "Le niveau d'alerte est obligatoire")
    @Size(max = 20, message = "Le niveau d'alerte ne peut pas dépasser 20 caractères")
    private String niveauAlerte; // normal, warning, critical

    @Size(max = 50, message = "L'icône ne peut pas dépasser 50 caractères")
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
    @Builder.Default
    private Integer prioritePreleveur = 1; // 1=normale, 2=prioritaire, 3=urgente

    @Builder.Default
    private Integer tempsSupplementaireMinutes = 0;

    @Builder.Default
    private Boolean actif = true;
}