package com.lims.patient.dto.response;

import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.PatientStatus;
import lombok.Builder;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * DTO résumé pour la liste des patients
 */
@Builder
public record PatientSummaryResponse(
        String id,
        String nomComplet,
        String email,
        String telephone,
        LocalDate dateNaissance,
        String numeroSecuMasque,
        Integer age,
        GenderType sexe,
        String ville,
        PatientStatus statut,
        LocalDateTime dateCreation
) {}