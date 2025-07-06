package com.lims.patient.mapper;

import com.lims.patient.dto.config.PatientBusinessRules;
import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;

/**
 * Mapper pour les configurations
 */
@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.IGNORE
)
public interface PatientConfigMapper {

    /**
     * Convertit les règles métier en DTO de configuration
     */
    PatientBusinessRules toPatientBusinessRules(
            Integer maxContactsParType,
            Integer maxAdressesParType,
            Integer maxAssurancesParPatient,
            Boolean validationEmailObligatoire,
            Boolean validationTelephoneObligatoire,
            Integer dureeConservationAuditJours,
            Boolean softDeleteUniquement
    );
}