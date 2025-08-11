package com.lims.laboratory.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entité représentant une analyse spécifique personnalisée par un laboratoire
 * Correspond exactement à la table laboratoire_analyse du schéma lims_laboratoire
 */
@Entity
@Table(name = "laboratoire_analyse", schema = "lims_laboratoire",
        indexes = {
                @Index(name = "idx_laboratoire_analyse_labo_id", columnList = "laboratoire_id"),
                @Index(name = "idx_laboratoire_analyse_examen_id", columnList = "laboratoire_examen_id"),
                @Index(name = "idx_laboratoire_analyse_ref_id", columnList = "analyse_referentiel_id"),
                @Index(name = "idx_laboratoire_analyse_sous_traite", columnList = "sous_traite")
        },
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_laboratoire_analyse_code",
                        columnNames = {"laboratoire_id", "code_analyse_labo"})
        })
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(callSuper = false)
public class LaboratoireAnalyse {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    // === RÉFÉRENCES ===

    @Column(name = "laboratoire_id", nullable = false)
    @NotNull(message = "L'identifiant du laboratoire est obligatoire")
    private UUID laboratoireId;

    @Column(name = "laboratoire_examen_id", nullable = false)
    @NotNull(message = "L'identifiant de l'examen laboratoire est obligatoire")
    private UUID laboratoireExamenId;

    @Column(name = "analyse_referentiel_id", nullable = false)
    @NotNull(message = "L'identifiant de l'analyse référentiel est obligatoire")
    private UUID analyseReferentielId;

    // === PERSONNALISATIONS DU LABORATOIRE ===

    @Column(name = "nom_analyse_labo", length = 500)
    @Size(max = 500, message = "Le nom de l'analyse ne peut dépasser 500 caractères")
    private String nomAnalyseLabo;

    @Column(name = "code_analyse_labo", length = 100)
    @Size(max = 100, message = "Le code de l'analyse ne peut dépasser 100 caractères")
    private String codeAnalyseLabo;

    // === INFORMATIONS TECHNIQUES ===

    @Column(name = "technique_utilisee", length = 200)
    @Size(max = 200, message = "La technique utilisée ne peut dépasser 200 caractères")
    private String techniqueUtilisee;

    @Column(name = "automate_utilise", length = 200)
    @Size(max = 200, message = "L'automate utilisé ne peut dépasser 200 caractères")
    private String automateUtilise;

    // === TARIFICATION ===

    @Column(name = "prix_coefficient", length = 10)
    @Size(max = 10, message = "Le coefficient prix ne peut dépasser 10 caractères")
    private String prixCoefficient; // Ex: "B12", "K15"

    @Column(name = "prix_analyse", precision = 10, scale = 2)
    @DecimalMin(value = "0.0", inclusive = true, message = "Le prix doit être positif ou nul")
    private BigDecimal prixAnalyse;

    // === VALEURS NORMALES ===

    @Column(name = "valeurs_normales_labo", columnDefinition = "TEXT")
    private String valeursNormalesLabo;

    // === CONFIGURATION ===

    @Column(name = "analyse_active", nullable = false)
    @Builder.Default
    private Boolean analyseActive = true;

    // === SOUS-TRAITANCE ===

    @Column(name = "sous_traite", nullable = false)
    @Builder.Default
    private Boolean sousTraite = false;

    @Column(name = "laboratoire_sous_traitant_id")
    private UUID laboratoireSousTraitantId;

    // === COMMENTAIRES ===

    @Column(name = "commentaires_technique", columnDefinition = "TEXT")
    private String commentairesTechnique;

    // === MÉTADONNÉES SYSTÈME ===

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // === RELATIONS JPA ===

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "laboratoire_id", insertable = false, updatable = false)
    private Laboratoire laboratoire;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "laboratoire_examen_id", insertable = false, updatable = false)
    private Examen examen;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "laboratoire_sous_traitant_id", insertable = false, updatable = false)
    private Laboratoire laboratoireSousTraitant;
}