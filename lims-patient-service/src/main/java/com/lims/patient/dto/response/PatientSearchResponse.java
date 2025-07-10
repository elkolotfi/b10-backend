package com.lims.patient.dto.response;

import lombok.Builder;

import java.util.List;

/**
 * DTO de réponse pour la recherche
 */
@Builder
public record PatientSearchResponse(
        List<PatientSummaryResponse> patients,
        int currentPage,
        int totalPages,
        long totalElements,
        int pageSize
) {}