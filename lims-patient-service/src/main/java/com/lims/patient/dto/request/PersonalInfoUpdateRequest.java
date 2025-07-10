package com.lims.patient.dto.request;

import com.lims.patient.enums.GenderType;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Size;
import lombok.Builder;

import java.time.LocalDate;

/**
 * DTO pour la mise à jour des informations personnelles
 */
@Builder
public record PersonalInfoUpdateRequest(
        @Size(max = 100)
        String nom,

        @Size(max = 100)
        String prenom,

        @Size(max = 100)
        String nomJeuneFille,

        @Past
        LocalDate dateNaissance,

        @Size(max = 100)
        String lieuNaissance,

        GenderType sexe,

        @Size(max = 255)
        String medecinTraitant,

        String allergiesConnues,

        String antecedentsMedicaux
) {}
