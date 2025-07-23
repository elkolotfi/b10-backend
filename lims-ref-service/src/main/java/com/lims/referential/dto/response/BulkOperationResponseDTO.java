package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Data
@Builder
public class BulkOperationResponseDTO {

    private String operation;
    private Integer totalRequested;
    private Integer successful;
    private Integer failed;
    private Integer skipped;
    private List<UUID> successfulIds;
    private Map<UUID, String> errors; // ID -> message d'erreur
    private LocalDateTime executedAt;
    private String summary;

    public static BulkOperationResponseDTO of(String operation, List<UUID> successful, Map<UUID, String> errors) {
        return BulkOperationResponseDTO.builder()
                .operation(operation)
                .totalRequested(successful.size() + errors.size())
                .successful(successful.size())
                .failed(errors.size())
                .skipped(0)
                .successfulIds(successful)
                .errors(errors)
                .executedAt(LocalDateTime.now())
                .summary(String.format("Opération %s: %d succès, %d échecs",
                        operation, successful.size(), errors.size()))
                .build();
    }
}