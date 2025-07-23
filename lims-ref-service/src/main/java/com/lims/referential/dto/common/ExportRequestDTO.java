package com.lims.referential.dto.common;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@Builder
public class ExportRequestDTO {

    @NotBlank(message = "Le format d'export est obligatoire")
    private String format; // csv, excel, json

    private List<String> columns;
    private Map<String, Object> filters;
    private String sortBy;
    private String sortDirection;
    private Integer maxRecords;
    private boolean includeHeaders;

    @Builder.Default
    private String encoding = "UTF-8";

    @Builder.Default
    private String delimiter = ",";
}