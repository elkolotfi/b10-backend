package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Data
@Builder
public class InteractionCheckDTO {

    private UUID medicamentId;
    private String medicamentNom;
    private List<String> analysesTestees;
    private List<InteractionDTO> interactionsDetectees;
    private String niveauCriticitéGlobal;
    private boolean arretRequis;
    private Integer delaiArretMaxHeures;
    private List<String> recommandations;
    private LocalDateTime checkedAt;

    @Data
    @Builder
    public static class InteractionDTO {
        private String codeNabm;
        private String nomAnalyse;
        private String typeInteraction;
        private String niveauCriticite;
        private String description;
        private Integer delaiArret;
        private String recommandation;
    }

    public static InteractionCheckDTO of(UUID medicamentId, String medicamentNom, List<String> analysesTestees) {
        return InteractionCheckDTO.builder()
                .medicamentId(medicamentId)
                .medicamentNom(medicamentNom)
                .analysesTestees(analysesTestees)
                .checkedAt(LocalDateTime.now())
                .build();
    }
}