package com.lims.referential.entity;

import com.lims.referential.entity.BaseEntity;
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

@Entity
@Table(name = "mutuelles", schema = "lims_referential")
@Where(clause = "deleted_at IS NULL")
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class Mutuelle extends BaseEntity {

    @Column(name = "nom", nullable = false)
    @NotBlank(message = "Le nom est obligatoire")
    @Size(max = 255)
    private String nom;

    @Column(name = "nom_commercial")
    @Size(max = 255)
    private String nomCommercial;

    @Column(name = "siret", length = 14)
    @Size(max = 14)
    private String siret;

    // Classification
    @Column(name = "type_organisme", length = 50)
    @Size(max = 50)
    private String typeOrganisme; // cpam, mutuelle, assurance, cmuc

    @Column(name = "code_organisme", length = 20)
    @Size(max = 20)
    private String codeOrganisme;

    @Column(name = "regime_rattachement", length = 100)
    @Size(max = 100)
    private String regimeRattachement;

    // Coordonnées
    @Column(name = "adresse_ligne1")
    @Size(max = 255)
    private String adresseLigne1;

    @Column(name = "adresse_ligne2")
    @Size(max = 255)
    private String adresseLigne2;

    @Column(name = "code_postal", length = 10)
    @Size(max = 10)
    private String codePostal;

    @Column(name = "ville", length = 100)
    @Size(max = 100)
    private String ville;

    @Column(name = "departement", length = 100)
    @Size(max = 100)
    private String departement;

    @Column(name = "region", length = 100)
    @Size(max = 100)
    private String region;

    // Contact
    @Column(name = "telephone", length = 20)
    private String telephone;

    @Column(name = "fax", length = 20)
    private String fax;

    @Column(name = "email")
    @Size(max = 255)
    private String email;

    @Column(name = "site_web")
    @Size(max = 255)
    private String siteWeb;

    // Informations de prise en charge
    @Builder.Default
    @Column(name = "taux_base_remboursement", precision = 5, scale = 2)
    private BigDecimal tauxBaseRemboursement = new BigDecimal("70.00");

    @Column(name = "plafond_annuel_euro", precision = 10, scale = 2)
    private BigDecimal plafondAnnuelEuro;

    @Builder.Default
    @Column(name = "franchise_euro", precision = 6, scale = 2)
    private BigDecimal franchiseEuro = BigDecimal.ZERO;

    // Analyses couvertes
    @Column(name = "analyses_couvertes", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<AnalyseCouverture> analysesCouvertes;

    @Column(name = "analyses_exclues", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> analysesExclues;

    // Facturation
    @Column(name = "codes_facturation", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> codesFacturation;

    @Builder.Default
    @Column(name = "delai_paiement_jours")
    private Integer delaiPaiementJours = 30;

    @Column(name = "mode_transmission", length = 50)
    @Size(max = 50)
    private String modeTransmission; // noemie, edifact, papier

    // Conventions spéciales
    @Column(name = "conventions_speciales", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> conventionsSpeciales;

    // Ajout du champ tiersPayant manquant
    @Column(name = "tiers_payant")
    private Boolean tiersPayant;

    @Builder.Default
    @Column(name = "actif", nullable = false)
    private Boolean actif = true;

    // Classe interne pour les analyses couvertes
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AnalyseCouverture {
        private String codeNabm;
        private BigDecimal tauxRemboursement;
        private BigDecimal plafond;
        private String conditions;
    }
}