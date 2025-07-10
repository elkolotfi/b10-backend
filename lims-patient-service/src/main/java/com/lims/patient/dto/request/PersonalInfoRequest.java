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
        @NotBlank @Size(max = 100)
        String nom,

        @NotBlank @Size(max = 100)
        String prenom,

        @Size(max = 100)
        String nomJeuneFille,

        @NotNull @Past
        LocalDate dateNaissance,

        @Size(max = 100)
        String lieuNaissance,

        @NotNull
        GenderType sexe,

        @NotBlank @Pattern(regexp = "^[12][0-9]{12}[0-9]{2}$", message = "Format NIR invalide")
        String numeroSecu,

        @Size(max = 255)
        String medecinTraitant,

        String allergiesConnues,

        String antecedentsMedicaux
) {}
