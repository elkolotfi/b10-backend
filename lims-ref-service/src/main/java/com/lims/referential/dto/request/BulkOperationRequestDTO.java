package com.lims.referential.dto.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Data
@Builder
public class BulkOperationRequestDTO {

    @NotNull(message = "L'opération est obligatoire")
    private String operation; // UPDATE, DELETE, ACTIVATE, DEACTIVATE

    @NotEmpty(message = "Au moins un ID doit être spécifié")
    private List<UUID> ids;

    private Map<String, Object> parameters; // Paramètres pour l'opération

    @Builder.Default
    private Boolean validateBeforeOperation = true;
}