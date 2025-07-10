package com.lims.patient.dto.response;


import com.lims.patient.enums.PatientStatus;
import lombok.Builder;

import java.time.LocalDateTime;

/**
 * DTO de réponse pour les métadonnées
 */
@Builder
public record MetadataResponse(
        PatientStatus statut,
        LocalDateTime dateCreation,
        LocalDateTime dateModification,
        String creePar,
        String modifiePar,
        Boolean actif
) {}

