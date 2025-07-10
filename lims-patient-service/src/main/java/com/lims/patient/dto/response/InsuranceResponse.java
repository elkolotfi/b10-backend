package com.lims.patient.dto.response;

import com.lims.patient.enums.InsuranceType;
import lombok.Builder;

import java.math.BigDecimal;
import java.time.LocalDate;

/**
 * DTO de réponse pour une assurance
 */
@Builder
public record InsuranceResponse(
        String id,
        InsuranceType typeAssurance,
        String nomOrganisme,
        String numeroAdherent,
        LocalDate dateDebut,
        LocalDate dateFin,
        Boolean estActive,
        Boolean tiersPayantAutorise,
        BigDecimal pourcentagePriseCharge,
        String referenceDocument
) {}
