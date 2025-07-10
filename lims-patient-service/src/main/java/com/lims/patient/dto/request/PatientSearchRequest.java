package com.lims.patient.dto.request;

import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.PatientStatus;
import lombok.Builder;

import java.time.LocalDate;

/**
 * DTO pour la recherche de patients
 */
@Builder
public record PatientSearchRequest(
        String nom,
        String prenom,
        String numeroSecu,
        String email,
        String telephone,
        String ville,
        String codePostal,
        LocalDate dateNaissance,
        GenderType sexe,
        PatientStatus statut,
        int page,
        int size,
        String sortBy,
        String sortDirection
) {}