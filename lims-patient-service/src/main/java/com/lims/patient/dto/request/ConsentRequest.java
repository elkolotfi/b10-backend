package com.lims.patient.dto.request;

import jakarta.validation.constraints.NotNull;
import lombok.Builder;

/**
 * DTO pour les consentements RGPD
 */
@Builder
public record ConsentRequest(
        @NotNull
        Boolean createAccount,

        @NotNull
        Boolean sms,

        @NotNull
        Boolean email
) {}
