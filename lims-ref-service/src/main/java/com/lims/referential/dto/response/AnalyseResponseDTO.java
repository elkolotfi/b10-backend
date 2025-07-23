package com.lims.referential.dto.response;

import com.lims.referential.entity.Analyse;
import com.lims.referential.enums.analyses.CategorieAnalyse;
import com.lims.referential.enums.analyses.NiveauUrgence;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;


@Data
@Builder
public class AnalyseResponseDTO {

    private UUID id;
    private String codeNabm;
    private String libelle;
    private String libelleAbrege;
    private String description;
    private CategorieAnalyse categorie;
    private String sousCategorie;
    private String methodeTechnique;
    private String uniteResultat;
    private Analyse.ValeursNormales valeursNormales;
    private Analyse.DelaiRendu delaiRendu;
    private List<Analyse.TubeRequis> tubesRequis;
    private Analyse.ConditionsPreAnalytiques conditionsPreAnalytiques;
    private Analyse.Tarif tarif;
    private NiveauUrgence niveauUrgence;
    private List<String> analysesAssociees;
    private List<String> contraindicationsRelatives;
    private String observationsSpeciales;
    private Boolean actif;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Integer version;
}
