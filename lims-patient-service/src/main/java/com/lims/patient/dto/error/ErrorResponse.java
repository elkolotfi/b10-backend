package com.lims.patient.dto.error;

import lombok.Builder;
import java.time.LocalDateTime;
import java.util.List;

@Builder
public record ErrorResponse(
        String code,
        String message,
        String detail,
        LocalDateTime timestamp,
        String path,
        List<FieldError> fieldErrors
) {}