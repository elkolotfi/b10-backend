package com.lims.patient.dto.request;

import jakarta.validation.constraints.NotNull;
import lombok.Builder;

/**
 * DTO pour les consentements RGPD
 */
@Builder
public record ConsentRequest(
        @NotNull
        Boolean consentementCreationCompte,

        @NotNull
        Boolean consentementSms,

        @NotNull
        Boolean consentementEmail
) {}
