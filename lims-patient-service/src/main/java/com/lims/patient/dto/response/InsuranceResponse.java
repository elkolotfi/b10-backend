package com.lims.patient.dto.response;

import com.lims.patient.enums.InsuranceType;
import lombok.Builder;

import java.time.LocalDate;
import java.time.LocalDateTime;

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
        Double pourcentagePriseCharge,
        String referenceDocument,
        LocalDateTime dateUploadDocument
) {}
