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

import java.util.List;

@Entity
@Table(name = "patient_specificities", schema = "lims_referential")
@Where(clause = "deleted_at IS NULL")
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class PatientSpecificity extends BaseEntity {

    @Column(name = "titre", nullable = false)
    @NotBlank(message = "Le titre est obligatoire")
    @Size(max = 255)
    private String titre;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "category_id", length = 50)
    @Size(max = 50)
    private String categoryId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "category_id", insertable = false, updatable = false)
    private SpecificityCategory category;

    // Niveau d'alerte
    @Column(name = "niveau_alerte", nullable = false, length = 20)
    @NotBlank(message = "Le niveau d'alerte est obligatoire")
    @Size(max = 20)
    private String niveauAlerte; // normal, warning, critical

    @Column(name = "icone", length = 50)
    @Size(max = 50)
    private String icone;

    // Mots-clés pour recherche
    @Column(name = "mots_cles", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> motsCles;

    // Instructions associées
    @Column(name = "instructions_preleveur", columnDefinition = "TEXT")
    private String instructionsPreleveur;

    @Column(name = "instructions_technique", columnDefinition = "TEXT")
    private String instructionsTechnique;

    @Column(name = "instructions_administrative", columnDefinition = "TEXT")
    private String instructionsAdministrative;

    // Contraintes pré-analytiques
    @Column(name = "impact_prelevements", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> impactPrelevements;

    @Column(name = "analyses_contre_indiquees", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> analysesContreIndiquees;

    @Column(name = "analyses_modifiees", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> analysesModifiees;

    // Priorité et temps
    @Builder.Default
    @Column(name = "priorite_preleveur")
    private Integer prioritePreleveur = 1; // 1=normale, 2=prioritaire, 3=urgente

    @Builder.Default
    @Column(name = "temps_supplementaire_minutes")
    private Integer tempsSupplementaireMinutes = 0;

    @Builder.Default
    @Column(name = "actif", nullable = false)
    private Boolean actif = true;
}