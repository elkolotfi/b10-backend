package com.lims.referential.dto.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class SynchronisationRequestDTO {

    @NotEmpty(message = "Au moins un domaine doit être spécifié")
    private List<String> domaines; // analyses, medecins, laboratoires, etc.

    @NotNull(message = "Le mode de synchronisation est obligatoire")
    @Builder.Default
    private String modeSync = "INCREMENTAL"; // INCREMENTAL, FULL

    @Builder.Default
    private Boolean forcerRemplacement = false;

    @Builder.Default
    private Boolean notifierResultat = true;

    private String sourceExterne; // URL ou nom de la source
}