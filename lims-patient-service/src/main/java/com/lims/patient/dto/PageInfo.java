package com.lims.patient.dto;

import lombok.Builder;

@Builder
public record PageInfo(
        Integer currentPage,
        Integer totalPages,
        Integer pageSize,
        Long totalElements,
        Boolean hasNext,
        Boolean hasPrevious
) {}
