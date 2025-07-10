package com.lims.patient.dto.request;

import lombok.Builder;

/**
 * DTO pour la mise à jour des consentements
 */
@Builder
public record ConsentUpdateRequest(
        Boolean consentementSms,
        Boolean consentementEmail
) {}
