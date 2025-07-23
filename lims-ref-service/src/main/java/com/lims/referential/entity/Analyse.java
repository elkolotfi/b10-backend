// Analyse.java
package com.lims.referential.entity;

import com.lims.referential.enums.analyses.TemperatureConservation;
import com.lims.referential.enums.analyses.*;
import com.lims.referential.enums.common.UniteTemps;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.Where;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

/**
 * Entité représentant une analyse biologique avec code NABM
 */
@Entity
@Table(name = "analyses", schema = "lims_referential")
@Where(clause = "deleted_at IS NULL")
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class Analyse extends BaseEntity {

    @Column(name = "code_nabm", unique = true, nullable = false, length = 10)
    @NotBlank(message = "Le code NABM est obligatoire")
    @Size(max = 10, message = "Le code NABM ne peut pas dépasser 10 caractères")
    private String codeNabm;

    @Column(name = "libelle", nullable = false)
    @NotBlank(message = "Le libellé est obligatoire")
    @Size(max = 255, message = "Le libellé ne peut pas dépasser 255 caractères")
    private String libelle;

    @Column(name = "libelle_abrege", length = 50)
    @Size(max = 50, message = "Le libellé abrégé ne peut pas dépasser 50 caractères")
    private String libelleAbrege;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "categorie", length = 100)
    @Enumerated(EnumType.STRING)
    private CategorieAnalyse categorie;

    @Column(name = "sous_categorie", length = 100)
    private String sousCategorie;

    @Column(name = "methode_technique", length = 100)
    private String methodeTechnique;

    @Column(name = "unite_resultat", length = 20)
    private String uniteResultat;

    // Valeurs normales stockées en JSON
    @Column(name = "valeurs_normales", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private ValeursNormales valeursNormales;

    // Délai de rendu
    @Column(name = "delai_rendu", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private DelaiRendu delaiRendu;

    // Tubes requis stockés en JSON
    @Column(name = "tubes_requis", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<TubeRequis> tubesRequis;

    // Conditions pré-analytiques
    @Column(name = "conditions_pre_analytiques", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private ConditionsPreAnalytiques conditionsPreAnalytiques;

    // Tarification
    @Column(name = "tarif", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private Tarif tarif;

    @Column(name = "niveau_urgence")
    @Enumerated(EnumType.STRING)
    private NiveauUrgence niveauUrgence;

    // Analyses associées (codes NABM)
    @Column(name = "analyses_associees", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> analysesAssociees;

    @Column(name = "contrindications_relatives", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> contraindicationsRelatives;

    @Column(name = "observations_speciales", columnDefinition = "TEXT")
    private String observationsSpeciales;

    @Builder.Default
    @Column(name = "actif", nullable = false)
    private Boolean actif = true;

    // Classes internes pour les structures JSON
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ValeursNormales {
        private BigDecimal min;
        private BigDecimal max;
        private String unite;
        private String commentaire;
        private Map<String, Object> valeursParAge;
        private Map<String, Object> valeursParSexe;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DelaiRendu {
        private Integer valeur;
        private UniteTemps unite;
        private Integer valeurUrgent;
        private UniteTemps uniteUrgent;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TubeRequis {
        private TypeTube type;
        private BigDecimal volume;
        private CouleurTube couleur;
        private Boolean obligatoire;
        private String commentaire;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ConditionsPreAnalytiques {
        private Boolean jeune;
        private Integer dureeJeune;
        private PositionPatient positionPatient;
        private List<String> medicamentsArreter;
        private String instructionsSpeciales;
        private Integer delaiStabilite;
        private TemperatureConservation temperatureConservation;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Tarif {
        private BigDecimal prixPublic;
        private Integer coefficientB;
        private Boolean remboursementSecu;
        private Integer tauxRemboursement;
        private BigDecimal prixConventionne;
    }
}

