package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Builder
public class CacheStatsDTO {

    private String cacheName;
    private Long hitCount;
    private Long missCount;
    private Long evictionCount;
    private Double hitRatio;
    private Long estimatedSize;
    private LocalDateTime lastAccess;
    private Map<String, Object> additionalMetrics;

    public static CacheStatsDTO of(String cacheName, Map<String, Object> stats) {
        return CacheStatsDTO.builder()
                .cacheName(cacheName)
                .hitCount((Long) stats.getOrDefault("hitCount", 0L))
                .missCount((Long) stats.getOrDefault("missCount", 0L))
                .evictionCount((Long) stats.getOrDefault("evictionCount", 0L))
                .hitRatio((Double) stats.getOrDefault("hitRatio", 0.0))
                .estimatedSize((Long) stats.getOrDefault("estimatedSize", 0L))
                .lastAccess(LocalDateTime.now())
                .additionalMetrics(stats)
                .build();
    }
}