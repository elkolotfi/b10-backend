package com.lims.patient.dto.config;

import lombok.Builder;

/**
 * DTO pour la configuration des règles métier patient
 */
@Builder
public record PatientBusinessRules(
        Integer maxContactsParType,
        Integer maxAdressesParType,
        Integer maxAssurancesParPatient,
        Boolean validationEmailObligatoire,
        Boolean validationTelephoneObligatoire,
        Integer dureeConservationAuditJours,
        Boolean softDeleteUniquement
) {
    // Valeurs par défaut
    public static PatientBusinessRules defaults() {
        return PatientBusinessRules.builder()
                .maxContactsParType(3)
                .maxAdressesParType(2)
                .maxAssurancesParPatient(5)
                .validationEmailObligatoire(true)
                .validationTelephoneObligatoire(false)
                .dureeConservationAuditJours(2555) // 7 ans
                .softDeleteUniquement(true)
                .build();
    }
}