package com.lims.laboratory.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entité représentant un prélèvement personnalisé par un laboratoire pour un examen
 * Table: lims_laboratoire.laboratoire_prelevement
 */
@Entity
@Table(name = "laboratoire_prelevement", schema = "lims_laboratoire")
@Data
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class LaboratoirePrelevement {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    // === RÉFÉRENCES OBLIGATOIRES ===

    @Column(name = "laboratoire_id", nullable = false)
    private UUID laboratoireId;

    @Column(name = "laboratoire_examen_id", nullable = false)
    private UUID laboratoireExamenId;

    @Column(name = "nature_prelevement_code", nullable = false, length = 20)
    private String naturePrelevementCode; // FK vers lims_referential.nature_prelevement(code)

    // === RELATIONS ===

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "laboratoire_id", insertable = false, updatable = false)
    private Laboratoire laboratoire;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "laboratoire_examen_id", insertable = false, updatable = false)
    private Examen laboratoireExamen;

    // === PERSONNALISATIONS DU LABORATOIRE ===

    @Column(name = "nom_prelevement_labo", length = 200)
    private String nomPrelevementLabo;

    // === SPÉCIFICATIONS DES TUBES ===

    @Column(name = "type_tube_labo", length = 100)
    private String typeTubeLabo;

    @Column(name = "couleur_tube", length = 50)
    private String couleurTube;

    @Column(name = "volume_recommande", length = 50)
    private String volumeRecommande; // en mL

    // === INSTRUCTIONS SPÉCIFIQUES ===

    @Column(name = "instructions_prelevement", columnDefinition = "TEXT")
    private String instructionsPrelevement;

    // === TARIFICATION DU PRÉLÈVEMENT ===

    @Column(name = "prix_coefficient_prelevement", length = 10)
    private String prixCoefficientPrelevement; // Coefficient NABM (ex: "P5", "P10")

    @Column(name = "prix_prelevement", precision = 10, scale = 2)
    private BigDecimal prixPrelevement; // Prix calculé ou prix libre

    // === CONFIGURATION ===

    @Column(name = "prelevement_obligatoire", nullable = false)
    private Boolean prelevementObligatoire = true;

    @Column(name = "ordre_prelevement", nullable = false)
    private Integer ordrePrelevement = 1;

    // === MÉTADONNÉES SYSTÈME ===

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    // === CONTRAINTES DE VALIDATION ===

    @PrePersist
    @PreUpdate
    private void validateConstraints() {
        if (ordrePrelevement != null && ordrePrelevement <= 0) {
            throw new IllegalArgumentException("L'ordre de prélèvement doit être positif");
        }
    }
}