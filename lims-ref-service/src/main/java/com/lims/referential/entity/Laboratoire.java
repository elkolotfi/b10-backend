package com.lims.referential.entity;

import com.lims.referential.enums.laboratoires.SpecialiteTechnique;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Entité représentant un laboratoire d'analyses médicales.
 */
@Entity
@Table(name = "laboratoires", schema = "lims_referential")
@EntityListeners(AuditingEntityListener.class)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@ToString(exclude = {"dateCreation", "dateModification"})
public class Laboratoire {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    @EqualsAndHashCode.Include
    private UUID id;

    @Column(name = "nom", nullable = false, length = 255)
    private String nom;

    @Column(name = "description", length = 500)
    private String description;

    @Column(name = "adresse", nullable = false, length = 500)
    private String adresse;

    @Column(name = "ville", nullable = false, length = 100)
    private String ville;

    @Column(name = "code_postal", nullable = false, length = 10)
    private String codePostal;

    @Column(name = "pays", length = 100)
    private String pays;

    // ============================================
    // INFORMATIONS DE CONTACT
    // ============================================

    @Column(name = "telephone", length = 20)
    private String telephone;

    @Column(name = "fax", length = 20)
    private String fax;

    @Column(name = "email", length = 255)
    private String email;

    @Column(name = "site_web", length = 255)
    private String siteWeb;

    // ============================================
    // INFORMATIONS PRATIQUES
    // ============================================

    @Column(name = "horaires_ouverture", length = 500)
    private String horairesOuverture;

    @Column(name = "parking_disponible")
    @Builder.Default
    private Boolean parkingDisponible = false;

    @Column(name = "acces_handicapes")
    @Builder.Default
    private Boolean accesHandicapes = false;

    @Column(name = "transport_public", length = 255)
    private String transportPublic;

    // ============================================
    // CAPACITÉS TECHNIQUES (stockées en JSON ou liste séparées par virgules)
    // ============================================
    @Column(name = "analyses_disponibles", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> analysesDisponibles;

    @Column(name = "specialites_techniques", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<SpecialiteTechnique> specialitesTechniques;

    @Column(name = "equipements_speciaux", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> equipementsSpeciaux;

    // ============================================
    // STATUT ET AUDIT
    // ============================================

    @Column(name = "actif", nullable = false)
    @Builder.Default
    private Boolean actif = true;

    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;

    @CreatedDate
    @Column(name = "date_creation", nullable = false, updatable = false)
    private LocalDateTime dateCreation;

    @LastModifiedDate
    @Column(name = "date_modification")
    private LocalDateTime dateModification;

    @CreatedBy
    @Column(name = "cree_par", length = 100, updatable = false)
    private String creePar;

    @LastModifiedBy
    @Column(name = "modifie_par", length = 100)
    private String modifiePar;

    @Version
    @Column(name = "version")
    private Long version;

    // ============================================
    // MÉTHODES UTILITAIRES
    // ============================================

    /**
     * Désactive le laboratoire (soft delete)
     */
    public void desactiver() {
        this.actif = false;
    }

    /**
     * Réactive le laboratoire
     */
    public void reactiver() {
        this.actif = true;
    }

    /**
     * Marque le laboratoire comme supprimé (soft delete)
     */
    public void markAsDeleted() {
        this.deletedAt = LocalDateTime.now();
        this.actif = false;
    }

    /**
     * Vérifie si le laboratoire est supprimé
     */
    public boolean isDeleted() {
        return this.deletedAt != null;
    }

    /**
     * Restaure un laboratoire supprimé
     */
    public void restore() {
        this.deletedAt = null;
        this.actif = true;
    }

    /**
     * Vérifie si le laboratoire a un contact email
     */
    public boolean hasEmail() {
        return this.email != null && !this.email.trim().isEmpty();
    }

    /**
     * Vérifie si le laboratoire propose une analyse spécifique
     */
    public boolean proposeAnalyse(String codeAnalyse) {
        return this.analysesDisponibles != null &&
                this.analysesDisponibles.contains(codeAnalyse);
    }

    // ============================================
    // CALLBACKS JPA
    // ============================================

    @PrePersist
    protected void onCreate() {
        if (this.actif == null) {
            this.actif = true;
        }
        if (this.parkingDisponible == null) {
            this.parkingDisponible = false;
        }
        if (this.accesHandicapes == null) {
            this.accesHandicapes = false;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        // Validation métier avant mise à jour
        if (this.email != null) {
            this.email = this.email.toLowerCase().trim();
        }
    }

    /**
     * Requête personnalisée pour exclure les éléments supprimés
     */
    @PreRemove
    protected void onRemove() {
        // Au lieu de supprimer physiquement, marquer comme supprimé
        markAsDeleted();
    }
}