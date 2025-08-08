package com.lims.laboratory.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entité représentant une analyse spécifique d'un examen dans un laboratoire
 * Correspond à la table laboratoire_analyse
 */
@Entity
@Table(name = "laboratoire_analyse", schema = "lims_laboratoire")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Analyse {

    @Id
    @GeneratedValue(generator = "UUID")
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    // === Relations ===

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "laboratoire_id", nullable = false)
    private Laboratoire laboratoire;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "laboratoire_examen_id", nullable = false)
    private Examen examen;

    @Column(name = "analyse_referentiel_id", nullable = false)
    private UUID analyseReferentielId; // FK vers lims_referential.analyse_porteuse_resultat(id)

    // === Personnalisations du laboratoire ===

    @Column(name = "nom_analyse_labo", length = 500)
    private String nomAnalyseLabo;

    @Column(name = "code_analyse_labo", length = 100)
    private String codeAnalyseLabo;

    // === Informations techniques ===

    @Column(name = "technique_utilisee", length = 200)
    private String techniqueUtilisee;

    @Column(name = "automate_utilise", length = 200)
    private String automateUtilise;

    // === Tarification ===

    @Column(name = "prix_coefficient", length = 10)
    private String prixCoefficient; // Coefficient NABM (ex: "B12", "K15")

    @Column(name = "prix_analyse", precision = 10, scale = 2)
    private BigDecimal prixAnalyse; // Prix calculé automatiquement ou prix libre

    // === Valeurs de référence ===

    @Column(name = "valeurs_normales_labo")
    private String valeursNormalesLabo; // Valeurs normales spécifiques au labo

    // === Configuration ===

    @Builder.Default
    @Column(name = "analyse_active", nullable = false)
    private Boolean analyseActive = true;

    @Builder.Default
    @Column(name = "sous_traite", nullable = false)
    private Boolean sousTraite = false;

    // === Métadonnées système ===

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
}