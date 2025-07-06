package com.lims.patient.dto;

import lombok.Builder;

@Builder
public record SearchStats(
        Long totalPatients,
        Long patientsActifs,
        Long patientsAvecAssurance,
        Long patientsAvecOrdonnance,
        Long nouveauxPatientsMoisCourant
) {}
