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

        @NotNull @FutureOrPresent
        LocalDate dateDebut,

        @Future
        LocalDate dateFin,

        Boolean tiersPayantAutorise,

        @DecimalMin("0.0") @DecimalMax("100.0")
        BigDecimal pourcentagePriseCharge,

        String referenceDocument // Clé MinIO du document justificatif
) {}
