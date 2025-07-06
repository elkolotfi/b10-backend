package com.lims.patient.dto.request;

import com.lims.patient.enums.GenderType;
import com.lims.patient.validation.ValidNIR;
import jakarta.validation.constraints.*;
import lombok.Builder;

import java.time.LocalDate;

/**
 * DTO pour les informations personnelles du patient
 */
@Builder
public record PersonalInfoRequest(
        @NotBlank @Size(min = 2, max = 100, message = "Le nom doit contenir entre 2 et 100 caractères")
        String nom,

        @NotBlank @Size(min = 2, max = 100, message = "Le prénom doit contenir entre 2 et 100 caractères")
        String prenom,

        @Size(max = 100)
        String nomJeuneFille,

        @NotNull @Past(message = "La date de naissance doit être dans le passé")
        LocalDate dateNaissance,

        @Size(max = 100)
        String lieuNaissance,

        @NotNull
        GenderType sexe,

        @ValidNIR
        String numeroSecu,

        @Size(max = 255)
        String medecinTraitant,

        @Size(max = 1000)
        String allergiesConnues,

        @Size(max = 2000)
        String antecedentsMedicaux,

        @Pattern(regexp = "^(fr-FR|en-US|es-ES|de-DE|it-IT)$")
        String languePreferee
) {}
