package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class AnalyseInteractionResponseDTO {

    private List<String> analysesTestees;
    private List<InteractionDetailDTO> interactions;
    private String niveauCriticitéGlobal;
    private List<String> recommandationsGenerales;
    private LocalDateTime analyseLe;

    @Data
    @Builder
    public static class InteractionDetailDTO {
        private String codeNabm;
        private String nomAnalyse;
        private List<MedicamentInteractionDTO> medicamentsInteragissant;
        private List<SpecificiteInteractionDTO> specificitesInteragissantes;
    }

    @Data
    @Builder
    public static class MedicamentInteractionDTO {
        private UUID medicamentId;
        private String nomCommercial;
        private String dci;
        private String typeInteraction;
        private String niveauCriticite;
        private Integer delaiArret;
        private String recommandation;
    }

    @Data
    @Builder
    public static class SpecificiteInteractionDTO {
        private UUID specificiteId;
        private String titre;
        private String niveauAlerte;
        private String typeImpact; // CONTRE_INDICATION, MODIFICATION, PRECAUTION
        private String instruction;
    }
}