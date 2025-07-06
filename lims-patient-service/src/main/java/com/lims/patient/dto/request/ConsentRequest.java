package com.lims.patient.dto.request;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;

/**
 * DTO pour les consentements RGPD
 */
@Builder
public record ConsentRequest(
        @NotNull(message = "Le consentement pour la création de compte est obligatoire")
        @AssertTrue(message = "Le consentement pour la création de compte doit être accepté")
        Boolean consentementCreationCompte,

        @NotNull
        Boolean consentementSms,

        @NotNull
        Boolean consentementEmail
) {}
