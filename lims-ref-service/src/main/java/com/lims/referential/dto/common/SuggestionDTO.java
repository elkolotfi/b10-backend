package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.util.UUID;

@Data
@Builder
public class SuggestionDTO {

    private UUID id;
    private String value;
    private String label;
    private String description;
    private String category;
    private Integer relevanceScore;
    private Object metadata;

    public static SuggestionDTO of(UUID id, String value, String label) {
        return SuggestionDTO.builder()
                .id(id)
                .value(value)
                .label(label)
                .relevanceScore(100)
                .build();
    }

    public static SuggestionDTO of(UUID id, String value, String label, String description) {
        return SuggestionDTO.builder()
                .id(id)
                .value(value)
                .label(label)
                .description(description)
                .relevanceScore(100)
                .build();
    }
}