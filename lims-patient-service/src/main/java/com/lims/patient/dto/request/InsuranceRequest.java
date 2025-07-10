package com.lims.patient.dto.request;

import com.lims.patient.enums.InsuranceType;
import jakarta.validation.constraints.*;
import lombok.Builder;

import java.math.BigDecimal;
import java.time.LocalDate;

/**
 * DTO pour une assurance
 */
@Builder
public record InsuranceRequest(
        @NotNull
        InsuranceType typeAssurance,

        @NotBlank @Size(max = 255)
        String nomOrganisme,

        @NotBlank @Size(max = 100)
        String numeroAdherent,

        @NotNull
        LocalDate dateDebut,

        LocalDate dateFin,

        Boolean tiersPayantAutorise,

        @DecimalMin("0.00") @DecimalMax("100.00")
        BigDecimal pourcentagePriseCharge,

        @Size(max = 500)
        String referenceDocument
) {}
