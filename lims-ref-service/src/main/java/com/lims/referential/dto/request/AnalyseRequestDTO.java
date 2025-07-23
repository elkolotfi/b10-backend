package com.lims.referential.dto.request;

import com.lims.referential.entity.Analyse;
import com.lims.referential.enums.analyses.CategorieAnalyse;
import com.lims.referential.enums.analyses.NiveauUrgence;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class AnalyseRequestDTO {

    @NotBlank(message = "Le code NABM est obligatoire")
    @Size(max = 10, message = "Le code NABM ne peut pas dépasser 10 caractères")
    private String codeNabm;

    @NotBlank(message = "Le libellé est obligatoire")
    @Size(max = 255, message = "Le libellé ne peut pas dépasser 255 caractères")
    private String libelle;

    @Size(max = 50, message = "Le libellé abrégé ne peut pas dépasser 50 caractères")
    private String libelleAbrege;

    private String description;

    @NotNull(message = "La catégorie est obligatoire")
    private CategorieAnalyse categorie;

    private String sousCategorie;
    private String methodeTechnique;
    private String uniteResultat;

    @Valid
    private Analyse.ValeursNormales valeursNormales;

    @Valid
    @NotNull(message = "Le délai de rendu est obligatoire")
    private Analyse.DelaiRendu delaiRendu;

    @Valid
    private List<Analyse.TubeRequis> tubesRequis;

    @Valid
    private Analyse.ConditionsPreAnalytiques conditionsPreAnalytiques;

    @Valid
    private Analyse.Tarif tarif;

    private NiveauUrgence niveauUrgence = NiveauUrgence.NORMAL;
    private List<String> analysesAssociees;
    private List<String> contraindicationsRelatives;
    private String observationsSpeciales;
    private Boolean actif = true;
}
