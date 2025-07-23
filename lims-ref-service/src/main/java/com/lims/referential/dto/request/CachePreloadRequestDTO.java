package com.lims.referential.dto.request;

import jakarta.validation.constraints.NotEmpty;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class CachePreloadRequestDTO {

    @NotEmpty(message = "Au moins un domaine doit être spécifié")
    private List<String> domaines;

    @Builder.Default
    private Boolean forcer = false; // Vider avant de précharger

    @Builder.Default
    private Boolean asynchrone = true;

    @Builder.Default
    private Integer batchSize = 100;
}