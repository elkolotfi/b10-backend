package com.lims.patient.dto.request;

import lombok.Builder;

@Builder
public record ConsentUpdateRequest(
        Boolean consentementSms,
        Boolean consentementEmail
) {}
