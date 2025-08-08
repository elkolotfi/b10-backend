package com.lims.laboratory.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entité représentant un type de prélèvement pour un examen dans un laboratoire
 * Correspond à la table laboratoire_prelevement (selon db_laboratoire_init)
 */
@Entity
@Table(name = "laboratoire_prelevement", schema = "lims_laboratoire")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Prelevement {

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

    @Column(name = "nom_prelevement_labo", length = 200)
    private String nomPrelevementLabo;

    // === Informations prélèvement (noms exacts selon db_laboratoire_init) ===

    @Column(name = "nature_prelevement_code", length = 20, nullable = false)
    private String naturePrelevementCode; // Code du type de prélèvement

    @Column(name = "volume_recommande", length = 50)
    private String volumeRecommande; // "5ml", "1 tube EDTA", etc.

    @Column(name = "type_tube_labo", length = 100)
    private String typeTubeLabo; // "EDTA", "Héparine", "Sec", etc.

    @Column(name = "couleur_tube", length = 50)
    private String couleurTube;

    // === Ordre et priorité ===

    @Builder.Default
    @Column(name = "ordre_prelevement", nullable = false)
    private Integer ordrePrelevement = 1; // Ordre de prélèvement

    // === Configuration (nouvelle colonne ajoutée) ===

    @Builder.Default
    @Column(name = "prelevement_actif", nullable = false)
    private Boolean prelevementActif = true;

    // === Métadonnées système ===

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
}