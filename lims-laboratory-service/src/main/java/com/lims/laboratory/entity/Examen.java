package com.lims.laboratory.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Entité représentant un examen personnalisé par un laboratoire
 * Correspond à la table laboratoire_examen
 */
@Entity
@Table(name = "laboratoire_examen", schema = "lims_laboratoire")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Examen {

    @Id
    @GeneratedValue(generator = "UUID")
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    // === Relations ===

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "laboratoire_id", nullable = false)
    private Laboratoire laboratoire;

    @Column(name = "examen_referentiel_id", nullable = false)
    private UUID examenReferentielId; // FK vers lims_referential.examen_prescriptible(id)

    // === Personnalisations du laboratoire ===

    @Column(name = "nom_examen_labo", length = 500)
    private String nomExamenLabo;

    // === Configuration de l'examen ===

    @Builder.Default
    @Column(name = "examen_actif", nullable = false)
    private Boolean examenActif = true;

    @Builder.Default
    @Column(name = "examen_realise_internement", nullable = false)
    private Boolean examenRealiseInternement = true;

    // === Délais de rendu ===

    @Column(name = "delai_rendu_habituel", length = 100)
    private String delaiRenduHabituel; // "24h", "2-3 jours", etc.

    @Column(name = "delai_rendu_urgent", length = 100)
    private String delaiRenduUrgent; // "2h", "dans la journée", etc.

    // === Conditions particulières ===

    @Column(name = "conditions_particulieres")
    private String conditionsParticulieres;

    // === Relations avec autres entités ===

    @OneToMany(mappedBy = "examen", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<Analyse> analyses = new ArrayList<>();

    @OneToMany(mappedBy = "examen", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<Prelevement> prelevements = new ArrayList<>();

    @OneToMany(mappedBy = "examen", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<Tarif> tarifs = new ArrayList<>();

    // === Métadonnées système ===

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    // === Contrainte unique ===
    @Table(uniqueConstraints = {
            @UniqueConstraint(name = "uk_laboratoire_examen_referentiel",
                    columnNames = {"laboratoire_id", "examen_referentiel_id"})
    })
    public static class ExamenConstraints {}
}