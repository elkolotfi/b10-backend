package com.lims.patient.dto.request;

import com.lims.patient.enums.GenderType;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;

import java.time.LocalDate;

@Builder
public record PersonalInfoUpdateRequest(
        @Size(min = 2, max = 100)
        String nom,

        @Size(min = 2, max = 100)
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

        @Size(max = 1000)
        String allergiesConnues,

        @Size(max = 2000)
        String antecedentsMedicaux,

        @Pattern(regexp = "^(fr-FR|en-US|es-ES|de-DE|it-IT)$")
        String languePreferee
) {}
