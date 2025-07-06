package com.lims.patient.dto.response;

import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record ConsentResponse(
        Boolean consentementCreationCompte,
        Boolean consentementSms,
        Boolean consentementEmail,
        LocalDateTime dateConsentement
) {}
