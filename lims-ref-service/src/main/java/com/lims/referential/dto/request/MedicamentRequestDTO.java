package com.lims.referential.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class MedicamentRequestDTO {

    @NotBlank(message = "Le nom commercial est obligatoire")
    @Size(max = 255, message = "Le nom commercial ne peut pas dépasser 255 caractères")
    private String nomCommercial;

    @NotBlank(message = "La DCI est obligatoire")
    @Size(max = 255, message = "La DCI ne peut pas dépasser 255 caractères")
    private String dci; // Dénomination Commune Internationale

    @Size(max = 13, message = "Le code CIP ne peut pas dépasser 13 caractères")
    private String codeCip;

    // Classification
    @Size(max = 100, message = "La classe thérapeutique ne peut pas dépasser 100 caractères")
    private String classeTherapeutique;

    @Size(max = 100, message = "La sous-classe ne peut pas dépasser 100 caractères")
    private String sousClasse;

    @Size(max = 100, message = "La forme pharmaceutique ne peut pas dépasser 100 caractères")
    private String formePharmaceutique;

    @Size(max = 100, message = "Le dosage ne peut pas dépasser 100 caractères")
    private String dosage;

    @Size(max = 100, message = "La voie d'administration ne peut pas dépasser 100 caractères")
    private String voieAdministration;

    // Interactions avec analyses
    private List<String> analysesImpactees; // Array des codes NABM

    @Size(max = 50, message = "Le type d'interaction ne peut pas dépasser 50 caractères")
    private String typeInteraction; // interference, faux_positif, faux_negatif

    @Size(max = 20, message = "Le niveau de criticité ne peut pas dépasser 20 caractères")
    private String niveauCriticite; // faible, modere, eleve, critique

    // Délais pré-analytiques
    @Builder.Default
    private Boolean arretRequis = false;

    @Builder.Default
    private Integer delaiArretHeures = 0;

    private String instructionsArret;

    // Informations complémentaires
    @Size(max = 255, message = "Le principe actif ne peut pas dépasser 255 caractères")
    private String principeActif;

    @Size(max = 255, message = "Le laboratoire fabricant ne peut pas dépasser 255 caractères")
    private String laboratoireFabricant;

    @Size(max = 50, message = "Le statut de commercialisation ne peut pas dépasser 50 caractères")
    private String statutCommercialisation; // commercialise, arrete, suspendu

    @Builder.Default
    private Boolean actif = true;
}