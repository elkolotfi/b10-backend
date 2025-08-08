package com.lims.laboratory.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
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
 * Entité représentant les tarifs spécifiques d'un laboratoire pour ses examens
 * Table: lims_laboratoire.laboratoire_tarif
 */
@Entity
@Table(
        name = "laboratoire_tarif",
        schema = "lims_laboratoire",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_laboratoire_tarif_type",
                        columnNames = {"laboratoire_examen_id", "type_tarif", "date_debut_validite"}
                )
        },
        indexes = {
                @Index(name = "idx_laboratoire_tarif_labo_id", columnList = "laboratoire_id"),
                @Index(name = "idx_laboratoire_tarif_examen_id", columnList = "laboratoire_examen_id"),
                @Index(name = "idx_laboratoire_tarif_type", columnList = "type_tarif"),
                @Index(name = "idx_laboratoire_tarif_validite", columnList = "date_debut_validite, date_fin_validite")
        }
)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Tarif {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    // === RÉFÉRENCES ===

    /**
     * Référence vers le laboratoire
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "laboratoire_id", nullable = false, foreignKey = @ForeignKey(name = "fk_laboratoire_tarif_laboratoire"))
    private Laboratoire laboratoire;

    /**
     * Référence vers l'examen du laboratoire
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "laboratoire_examen_id", nullable = false, foreignKey = @ForeignKey(name = "fk_laboratoire_tarif_examen"))
    private Examen examen;

    // === TYPE DE TARIF ===

    /**
     * Type de tarif
     * Valeurs possibles: 'public', 'conventionne', 'mutuelle', 'supplement', 'hors_nomenclature', 'urgence'
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "type_tarif", length = 50, nullable = false)
    @NotNull(message = "Le type de tarif est obligatoire")
    private TypeTarif typeTarif;

    // === MONTANT ET DEVISE ===

    /**
     * Montant du tarif
     */
    @Column(name = "montant", precision = 10, scale = 2, nullable = false)
    @NotNull(message = "Le montant est obligatoire")
    @DecimalMin(value = "0.0", inclusive = true, message = "Le montant doit être positif ou nul")
    private BigDecimal montant;

    /**
     * Devise (par défaut EUR)
     */
    @Column(name = "devise", length = 3, nullable = false)
    @Size(max = 3, message = "La devise ne peut pas dépasser 3 caractères")
    @Builder.Default
    private String devise = "EUR";

    // === NOMENCLATURE ===

    /**
     * Code nomenclature (NABM, CCAM, etc.)
     */
    @Column(name = "code_nomenclature", length = 20)
    @Size(max = 20, message = "Le code nomenclature ne peut pas dépasser 20 caractères")
    private String codeNomenclature;

    // === REMBOURSEMENT ===

    /**
     * Indique si le tarif est remboursable
     */
    @Column(name = "remboursable", nullable = false)
    @Builder.Default
    private Boolean remboursable = false;

    /**
     * Conditions de remboursement (texte libre)
     */
    @Column(name = "conditions_remboursement", columnDefinition = "TEXT")
    private String conditionsRemboursement;

    // === PÉRIODE DE VALIDITÉ ===

    /**
     * Date de début de validité du tarif
     */
    @Column(name = "date_debut_validite", nullable = false)
    @NotNull(message = "La date de début de validité est obligatoire")
    @Builder.Default
    private LocalDate dateDebutValidite = LocalDate.now();

    /**
     * Date de fin de validité du tarif (optionnelle)
     */
    @Column(name = "date_fin_validite")
    private LocalDate dateFinValidite;

    // === MÉTADONNÉES SYSTÈME ===

    /**
     * Date de création de l'enregistrement
     */
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * Date de dernière mise à jour
     */
    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    // === ÉNUMÉRATION TYPE TARIF ===

    /**
     * Types de tarifs possibles
     */
    public enum TypeTarif {
        PUBLIC("public"),
        CONVENTIONNE("conventionne"),
        MUTUELLE("mutuelle"),
        SUPPLEMENT("supplement"),
        HORS_NOMENCLATURE("hors_nomenclature"),
        URGENCE("urgence");

        private final String value;

        TypeTarif(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        /**
         * Méthode pour obtenir l'enum à partir de la valeur string
         */
        public static TypeTarif fromValue(String value) {
            for (TypeTarif type : TypeTarif.values()) {
                if (type.value.equals(value)) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Type de tarif inconnu: " + value);
        }
    }

    // === MÉTHODES UTILITAIRES ===

    /**
     * Vérifie si le tarif est actuellement valide
     */
    public boolean isCurrentlyValid() {
        LocalDate now = LocalDate.now();
        return (dateDebutValidite == null || !now.isBefore(dateDebutValidite)) &&
                (dateFinValidite == null || !now.isAfter(dateFinValidite));
    }

    /**
     * Vérifie si le tarif sera valide à une date donnée
     */
    public boolean isValidAt(LocalDate date) {
        return (dateDebutValidite == null || !date.isBefore(dateDebutValidite)) &&
                (dateFinValidite == null || !date.isAfter(dateFinValidite));
    }

    /**
     * Calcule le montant avec un coefficient multiplicateur
     */
    public BigDecimal calculateAmount(BigDecimal coefficient) {
        if (coefficient == null || montant == null) {
            return montant;
        }
        return montant.multiply(coefficient);
    }

    // === MÉTHODES POUR JPA ===

    /**
     * Méthode appelée avant la sauvegarde pour valider les données
     */
    @PrePersist
    @PreUpdate
    private void validateDatePeriod() {
        if (dateFinValidite != null && dateDebutValidite != null &&
                dateFinValidite.isBefore(dateDebutValidite)) {
            throw new IllegalArgumentException(
                    "La date de fin de validité ne peut pas être antérieure à la date de début"
            );
        }
    }

    @Override
    public String toString() {
        return "LaboratoireTarif{" +
                "id=" + id +
                ", typeTarif=" + typeTarif +
                ", montant=" + montant +
                ", devise='" + devise + '\'' +
                ", dateDebutValidite=" + dateDebutValidite +
                ", dateFinValidite=" + dateFinValidite +
                ", remboursable=" + remboursable +
                '}';
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        Tarif that = (Tarif) obj;
        return id != null && id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}