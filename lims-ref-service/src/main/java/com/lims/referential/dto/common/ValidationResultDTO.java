package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class ValidationResultDTO {

    private boolean valid;
    private String field;
    private Object value;
    private String message;
    private String errorCode;
    private List<String> suggestions;
    private Map<String, Object> context;
    private LocalDateTime validatedAt;

    public static ValidationResultDTO valid(String field, Object value) {
        return ValidationResultDTO.builder()
                .valid(true)
                .field(field)
                .value(value)
                .message("Validation réussie")
                .validatedAt(LocalDateTime.now())
                .build();
    }

    public static ValidationResultDTO invalid(String field, Object value, String message) {
        return ValidationResultDTO.builder()
                .valid(false)
                .field(field)
                .value(value)
                .message(message)
                .validatedAt(LocalDateTime.now())
                .build();
    }

    public static ValidationResultDTO invalid(String field, Object value, String message, String errorCode) {
        return ValidationResultDTO.builder()
                .valid(false)
                .field(field)
                .value(value)
                .message(message)
                .errorCode(errorCode)
                .validatedAt(LocalDateTime.now())
                .build();
    }
}