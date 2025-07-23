// lims-ref-service/src/main/java/com/lims/referential/entity/Medicament.java
package com.lims.referential.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entité représentant un médicament dans la base de données publique des médicaments.
 * Basée sur les données de l'ANSM (Agence nationale de sécurité du médicament).
 */
@Entity
@Table(name = "medicaments", schema = "lims_referential")
@EntityListeners(AuditingEntityListener.class)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@ToString(exclude = {"dateCreation", "dateModification"})
public class Medicament {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    @EqualsAndHashCode.Include
    private UUID id;

    /**
     * Code CIS (Code Identifiant de Spécialité)
     * Identifiant unique du médicament selon l'ANSM
     */
    @Column(name = "code_cis", nullable = false, unique = true, length = 50)
    private String codeCis;

    /**
     * Dénomination du médicament
     */
    @Column(name = "denomination", nullable = false, length = 500)
    private String denomination;

    /**
     * Forme pharmaceutique (comprimé, gélule, sirop, etc.)
     */
    @Column(name = "forme_pharma", length = 200)
    private String formePharma;

    /**
     * Voies d'administration (orale, injectable, etc.)
     */
    @Column(name = "voies_admin", length = 200)
    private String voiesAdmin;

    /**
     * Statut de l'Autorisation de Mise sur le Marché
     */
    @Column(name = "statut_amm", length = 100)
    private String statutAmm;

    /**
     * Type de procédure d'autorisation
     */
    @Column(name = "type_procedure", length = 100)
    private String typeProcedure;

    /**
     * Laboratoire titulaire de l'AMM
     */
    @Column(name = "laboratoire_titulaire", length = 300)
    private String laboratoireTitulaire;

    /**
     * Laboratoire exploitant le médicament
     */
    @Column(name = "laboratoire_exploitant", length = 300)
    private String laboratoireExploitant;

    /**
     * Date d'obtention de l'AMM
     */
    @Column(name = "date_amm")
    private LocalDateTime dateAmm;

    /**
     * Statut dans la Base de données publique des médicaments
     */
    @Column(name = "statut_bdm", length = 100)
    private String statutBdm;

    /**
     * Numéro d'autorisation européenne (si applicable)
     */
    @Column(name = "numero_autorisation_europeenne", length = 100)
    private String numeroAutorisationEuropeenne;

    /**
     * Liste des titulaires de l'AMM
     */
    @Column(name = "titulaires_amm", length = 500)
    private String titulairesAmm;

    /**
     * Indique si le médicament fait l'objet d'une surveillance renforcée
     */
    @Column(name = "surveillance_renforcee")
    @Builder.Default
    private Boolean surveillanceRenforcee = false;

    /**
     * Prix de vente public (en euros)
     */
    @Column(name = "prix_vente", precision = 10, scale = 2)
    private BigDecimal prixVente;

    /**
     * Taux de remboursement par la Sécurité sociale (en pourcentage)
     */
    @Column(name = "taux_remboursement")
    private Integer tauxRemboursement;

    /**
     * Indique si le médicament est actif/visible dans le système
     */
    @Column(name = "actif", nullable = false)
    @Builder.Default
    private Boolean actif = true;

    // ============================================
    // CHAMPS D'AUDIT AUTOMATIQUES
    // ============================================

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

    /**
     * Version pour l'optimistic locking
     */
    @Version
    @Column(name = "version")
    private Long version;

    // ============================================
    // MÉTHODES UTILITAIRES
    // ============================================

    /**
     * Désactive le médicament (soft delete)
     */
    public void desactiver() {
        this.actif = false;
    }

    /**
     * Réactive le médicament
     */
    public void reactiver() {
        this.actif = true;
    }

    /**
     * Vérifie si le médicament est remboursé
     */
    public boolean estRembourse() {
        return this.tauxRemboursement != null && this.tauxRemboursement > 0;
    }

    /**
     * Vérifie si le médicament est sous surveillance renforcée
     */
    public boolean estSousSurveillance() {
        return Boolean.TRUE.equals(this.surveillanceRenforcee);
    }

    // ============================================
    // CALLBACKS JPA
    // ============================================

    @PrePersist
    protected void onCreate() {
        if (this.actif == null) {
            this.actif = true;
        }
        if (this.surveillanceRenforcee == null) {
            this.surveillanceRenforcee = false;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        // Validation métier avant mise à jour
        if (this.codeCis != null) {
            this.codeCis = this.codeCis.toUpperCase().trim();
        }
    }
}