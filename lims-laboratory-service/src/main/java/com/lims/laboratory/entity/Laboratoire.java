package com.lims.laboratory.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Entité représentant un laboratoire
 * Table: lims_laboratoire.laboratoire
 */
@Entity
@Table(name = "laboratoire", schema = "lims_laboratoire")
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
public class Laboratoire {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", nullable = false)
    private UUID id;

    // === Identification du laboratoire ===

    @Column(name = "nom_commercial", nullable = false, length = 255)
    private String nomCommercial;

    @Column(name = "nom_legal", nullable = false, length = 255)
    private String nomLegal;

    @Column(name = "nom_laboratoire", length = 500)
    private String nomLaboratoire;

    @Column(name = "code_laboratoire", length = 100)
    private String codeLaboratoire;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "siret", length = 14, unique = true)
    private String siret;

    @Column(name = "numero_finess", length = 20, unique = true)
    private String numeroFiness;

    // === Type de laboratoire ===

    @Enumerated(EnumType.STRING)
    @Column(name = "type_laboratoire", length = 50)
    private TypeLaboratoire typeLaboratoire;

    // === Adresse et contact (format simple) ===

    @Column(name = "adresse", columnDefinition = "TEXT")
    private String adresse;

    @Column(name = "contact", columnDefinition = "TEXT")
    private String contact;

    // === Statut ===

    @Column(name = "actif", nullable = false)
    private Boolean actif = true;

    // === Métadonnées système ===

    @CreationTimestamp
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    /**
     * Énumération des types de laboratoires
     */
    public enum TypeLaboratoire {
        PRIVE("prive"),
        HOSPITALIER("hospitalier"),
        PUBLIC("public"),
        MIXTE("mixte"),
        RECHERCHE("recherche");

        private final String value;

        TypeLaboratoire(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        public static TypeLaboratoire fromValue(String value) {
            for (TypeLaboratoire type : TypeLaboratoire.values()) {
                if (type.value.equals(value)) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Type de laboratoire non reconnu : " + value);
        }
    }
}