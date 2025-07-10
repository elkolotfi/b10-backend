package com.lims.patient.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * DTO pour les statistiques des patients
 */
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PatientStatsResponse {
    private long totalPatientsActifs;
    private List<Object[]> statistiquesParStatut;
    private List<Object[]> statistiquesParSexe;
    private List<Object[]> statistiquesParVille;
}
