package com.lims.laboratory.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entité représentant les majorations applicables par un laboratoire
 * Correspond à la table laboratoire_majoration
 */
@Entity
@Table(name = "laboratoire_majoration", schema = "lims_laboratoire")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Majoration {

    @Id
    @GeneratedValue(generator = "UUID")
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    // === Relations ===

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "laboratoire_id", nullable = false)
    private Laboratoire laboratoire;

    // === Type de majoration ===

    @Enumerated(EnumType.STRING)
    @Column(name = "type_majoration", nullable = false, length = 50)
    private TypeMajoration typeMajoration;

    // === Montant ===

    @Column(name = "montant", precision = 10, scale = 2, nullable = false)
    private BigDecimal montant;

    // === Configuration ===

    @Builder.Default
    @Column(name = "active", nullable = false)
    private Boolean active = true;

    // === Période de validité ===

    @Builder.Default
    @Column(name = "date_debut_validite", nullable = false)
    private LocalDate dateDebutValidite = LocalDate.now();

    @Column(name = "date_fin_validite")
    private LocalDate dateFinValidite;

    // === Métadonnées système ===

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    // === Énumération des types de majorations ===

    public enum TypeMajoration {
        URGENCE("Majoration urgence"),
        DOMICILE("Majoration domicile"),
        NUIT("Majoration nuit"),
        WEEKEND("Majoration weekend"),
        FERIE("Majoration jour férié"),
        DEPLACEMENT("Frais de déplacement");

        private final String libelle;

        TypeMajoration(String libelle) {
            this.libelle = libelle;
        }

        public String getLibelle() {
            return libelle;
        }
    }
}