package com.lims.patient.mapper;

import com.lims.patient.dto.response.PatientInsuranceResponse;
import com.lims.patient.entity.PatientAssurance;
import org.springframework.stereotype.Component;

/**
 * Mapper pour convertir les entités PatientAssurance en DTOs.
 */
@Component
public class PatientInsuranceMapper {

    /**
     * Convertit une entité PatientAssurance en PatientInsuranceResponse.
     */
    public PatientInsuranceResponse toResponse(PatientAssurance assurance) {
        if (assurance == null) {
            return null;
        }

        return PatientInsuranceResponse.of(
                assurance.getId(),
                assurance.getPatient().getId(),
                assurance.getTypeAssurance(),
                assurance.getNomOrganisme(),
                assurance.getNumeroAdherent(),
                assurance.getDateDebut(),
                assurance.getDateFin(),
                assurance.getEstActive(),
                assurance.getTiersPayantAutorise(),
                assurance.getPourcentagePriseCharge(),
                assurance.getReferenceDocument(),
                assurance.getDateUploadDocument(),
                assurance.getDateCreation(),
                assurance.getDateModification()
        );
    }
}