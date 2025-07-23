package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class ImportResultDTO {

    private boolean success;
    private Integer totalRecords;
    private Integer successCount;
    private Integer errorCount;
    private Integer skippedCount;
    private List<String> errors;
    private Map<String, Object> summary;
    private LocalDateTime importedAt;
    private String filename;

    public static ImportResultDTO success(int total, int success, int errors, int skipped, String filename) {
        return ImportResultDTO.builder()
                .success(errors == 0)
                .totalRecords(total)
                .successCount(success)
                .errorCount(errors)
                .skippedCount(skipped)
                .filename(filename)
                .importedAt(LocalDateTime.now())
                .summary(Map.of(
                        "successRate", total > 0 ? (double) success / total * 100 : 0,
                        "hasErrors", errors > 0
                ))
                .build();
    }
}