package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class SearchCriteriaDTO {

    private String searchTerm;
    private Map<String, Object> filters;
    private Integer page;
    private Integer size;
    private String sortBy;
    private String sortDirection;

    public static SearchCriteriaDTO of(String searchTerm, int page, int size, String sort) {
        String[] sortParts = sort != null ? sort.split(",") : new String[]{"id", "asc"};
        String sortBy = sortParts.length > 0 ? sortParts[0] : "id";
        String sortDirection = sortParts.length > 1 ? sortParts[1] : "asc";

        return SearchCriteriaDTO.builder()
                .searchTerm(searchTerm)
                .page(page)
                .size(size)
                .sortBy(sortBy)
                .sortDirection(sortDirection)
                .build();
    }
}