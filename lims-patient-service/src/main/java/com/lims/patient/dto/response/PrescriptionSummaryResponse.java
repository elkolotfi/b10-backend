package com.lims.patient.dto.response;

import com.lims.patient.enums.PrescriptionStatus;
import lombok.Builder;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Builder
public record PrescriptionSummaryResponse(
        String id,
        String nomMedecin,
        String rppsMedecin,
        LocalDate datePrescription,
        PrescriptionStatus statut,
        Boolean estRenouvelable,
        LocalDate renouvelableJusqu,
        Integer nombreAnalyses,
        LocalDateTime dateCreation
) {}
