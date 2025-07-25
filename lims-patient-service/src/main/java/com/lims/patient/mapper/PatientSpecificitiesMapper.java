package com.lims.patient.mapper;

import com.lims.patient.dto.response.PatientResponse;
import com.lims.patient.dto.response.PatientSpecificitiesResponse;
import com.lims.patient.entity.Patient;
import org.mapstruct.Mapping;
import org.mapstruct.Named;

import java.util.List;

public interface PatientSpecificitiesMapper {
    @Named("toSpecificitiesResponse")
    default PatientSpecificitiesResponse toSpecificitiesResponse(Patient patient) {
        if (patient == null) return null;

        return PatientSpecificitiesResponse.builder()
                .specificityIds(patient.getSpecificityIds() != null ? patient.getSpecificityIds() : List.of())
                .build();
    }

    // Mapping principal
    @Mapping(target = "specificities", source = ".", qualifiedByName = "toSpecificitiesResponse")
    @Mapping(target = "commentairePatient", source = "commentairePatient") // DIRECTEMENT depuis patient
    PatientResponse toPatientResponse(Patient patient);
}
