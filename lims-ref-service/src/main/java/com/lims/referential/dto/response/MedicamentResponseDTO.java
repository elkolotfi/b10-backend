package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class MedicamentResponseDTO {

    private UUID id;
    private String nomCommercial;
    private String dci;
    private String codeCip;

    // Classification
    private String classeTherapeutique;
    private String sousClasse;
    private String formePharmaceutique;
    private String dosage;
    private String voieAdministration;

    // Interactions avec analyses
    private List<String> analysesImpactees;
    private String typeInteraction;
    private String niveauCriticite;

    // Délais pré-analytiques
    private Boolean arretRequis;
    private Integer delaiArretHeures;
    private String instructionsArret;

    // Informations complémentaires
    private String principeActif;
    private String laboratoireFabricant;
    private String statutCommercialisation;
    private Boolean actif;

    // Métadonnées
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Integer version;
}