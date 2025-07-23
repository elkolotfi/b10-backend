package com.lims.referential.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.util.List;

@Data
@Builder
public class GeographiqueRequestDTO {

    @NotBlank(message = "Le code postal est obligatoire")
    @Size(max = 10, message = "Le code postal ne peut pas dépasser 10 caractères")
    private String codePostal;

    @NotBlank(message = "Le nom de la commune est obligatoire")
    @Size(max = 255, message = "Le nom de la commune ne peut pas dépasser 255 caractères")
    private String nomCommune;

    @Size(max = 10, message = "Le code commune ne peut pas dépasser 10 caractères")
    private String codeCommune;

    // Hiérarchie administrative
    @NotBlank(message = "Le département est obligatoire")
    @Size(max = 100, message = "Le département ne peut pas dépasser 100 caractères")
    private String departement;

    @NotBlank(message = "Le code département est obligatoire")
    @Size(max = 3, message = "Le code département ne peut pas dépasser 3 caractères")
    private String codeDepartement;

    @NotBlank(message = "La région est obligatoire")
    @Size(max = 100, message = "La région ne peut pas dépasser 100 caractères")
    private String region;

    @NotBlank(message = "Le code région est obligatoire")
    @Size(max = 3, message = "Le code région ne peut pas dépasser 3 caractères")
    private String codeRegion;

    // Géolocalisation
    private BigDecimal latitude;
    private BigDecimal longitude;

    // Informations démographiques
    private Integer population;
    private BigDecimal superficieKm2;
    private BigDecimal densiteHabKm2;

    // Zone de desserte laboratoires
    private List<String> laboratoiresZone; // Array des IDs laboratoires
    private BigDecimal distanceLaboratoirePlusProcheKm;

    @Builder.Default
    private Boolean actif = true;
}