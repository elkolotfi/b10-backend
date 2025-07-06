package com.lims.patient.dto.error;

import lombok.Builder;

@Builder
public record FieldError(
        String field,
        Object rejectedValue,
        String message
) {}
