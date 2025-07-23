package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class SynchronisationResponseDTO {

    private String syncId;
    private List<String> domaines;
    private String modeSync;
    private String statut; // EN_COURS, TERMINE, ERREUR
    private LocalDateTime dateDebut;
    private LocalDateTime dateFin;
    private Map<String, SyncResultatDTO> resultatsParDomaine;
    private List<String> erreurs;
    private String message;

    @Data
    @Builder
    public static class SyncResultatDTO {
        private String domaine;
        private Integer totalTraite;
        private Integer ajoutes;
        private Integer modifies;
        private Integer supprimes;
        private Integer erreurs;
        private List<String> detailsErreurs;
    }
}