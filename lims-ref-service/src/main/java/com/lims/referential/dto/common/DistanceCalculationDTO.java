package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
public class DistanceCalculationDTO {

    private PointDTO origin;
    private PointDTO destination;
    private BigDecimal distanceKm;
    private BigDecimal distanceMiles;
    private String unit;
    private LocalDateTime calculatedAt;

    @Data
    @Builder
    public static class PointDTO {
        private BigDecimal latitude;
        private BigDecimal longitude;
        private String label;
        private String address;
    }

    public static DistanceCalculationDTO of(
            BigDecimal originLat, BigDecimal originLon,
            BigDecimal destLat, BigDecimal destLon,
            BigDecimal distanceKm) {

        return DistanceCalculationDTO.builder()
                .origin(PointDTO.builder()
                        .latitude(originLat)
                        .longitude(originLon)
                        .build())
                .destination(PointDTO.builder()
                        .latitude(destLat)
                        .longitude(destLon)
                        .build())
                .distanceKm(distanceKm)
                .distanceMiles(distanceKm.multiply(new BigDecimal("0.621371")))
                .unit("km")
                .calculatedAt(LocalDateTime.now())
                .build();
    }
}