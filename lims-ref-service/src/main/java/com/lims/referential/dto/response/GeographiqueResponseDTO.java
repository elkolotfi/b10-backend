package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class GeographiqueResponseDTO {

    private UUID id;
    private String codePostal;
    private String nomCommune;
    private String codeCommune;

    // Hiérarchie administrative
    private String departement;
    private String codeDepartement;
    private String region;
    private String codeRegion;

    // Géolocalisation
    private BigDecimal latitude;
    private BigDecimal longitude;

    // Informations démographiques
    private Integer population;
    private BigDecimal superficieKm2;
    private BigDecimal densiteHabKm2;

    // Zone de desserte laboratoires
    private List<String> laboratoiresZone;
    private BigDecimal distanceLaboratoirePlusProcheKm;
    private Boolean actif;

    // Métadonnées
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Integer version;
}