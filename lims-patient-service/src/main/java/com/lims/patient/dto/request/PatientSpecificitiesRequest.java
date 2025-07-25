package com.lims.patient.dto.request;

import lombok.Builder;
import java.util.List;

/**
 * DTO pour les spécificités du patient - Version minimaliste selon accords
 */
@Builder
public record PatientSpecificitiesRequest(
        List<String> specificityIds // UNIQUEMENT les IDs, pas plus
) {}