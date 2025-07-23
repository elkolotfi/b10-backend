package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Builder
public class StatisticsDTO {

    private String domain;
    private Map<String, Object> metrics;
    private LocalDateTime generatedAt;
    private String period;

    public static StatisticsDTO of(String domain, Map<String, Object> metrics) {
        return StatisticsDTO.builder()
                .domain(domain)
                .metrics(metrics)
                .generatedAt(LocalDateTime.now())
                .period("current")
                .build();
    }
}