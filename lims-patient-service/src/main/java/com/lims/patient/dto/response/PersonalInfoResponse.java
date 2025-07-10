package com.lims.patient.dto.response;

// import com.lims.patient.dto.request.GenderType;
import com.lims.patient.enums.GenderType;
import lombok.Builder;

import java.time.LocalDate;

/**
 * DTO de réponse pour les informations personnelles
 */
@Builder
public record PersonalInfoResponse(
        String nom,
        String prenom,
        String nomJeuneFille,
        LocalDate dateNaissance,
        String lieuNaissance,
        GenderType sexe,
        String numeroSecuMasque,
        Integer age,
        String medecinTraitant,
        String allergiesConnues,
        String antecedentsMedicaux
) {}
