package com.lims.patient.dto.response;

import com.lims.patient.dto.PageInfo;
import com.lims.patient.dto.SearchStats;
import lombok.Builder;

import java.util.List;

/**
 * DTO pour les résultats de recherche paginés
 */
@Builder
public record PatientSearchResponse(
        List<PatientSummaryResponse> patients,
        PageInfo pageInfo,
        SearchStats stats
) {}
