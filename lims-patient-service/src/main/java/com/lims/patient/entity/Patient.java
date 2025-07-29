package com.lims.patient.entity;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.lims.patient.enums.DeliveryMethod;
import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.NotificationPreference;
import com.lims.patient.enums.PatientStatus;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Entité principale Patient - Version centralisée
 * Contient les données civiles obligatoires et les informations de contact centralisées
 */
@Entity
@Table(name = "patients", schema = "lims_patient")
@EntityListeners(AuditingEntityListener.class)
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Patient {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // ===== IDENTIFICATION CIVILE =====
    @Column(name = "nom", nullable = false, length = 100)
    private String nom;

    @Column(name = "prenom", nullable = false, length = 100)
    private String prenom;

    @Column(name = "nom_jeune_fille", length = 100)
    private String nomJeuneFille;

    @Column(name = "date_naissance", nullable = false)
    private LocalDate dateNaissance;

    @Column(name = "lieu_naissance", length = 100)
    private String lieuNaissance;

    @Enumerated(EnumType.STRING)
    @Column(name = "sexe", nullable = false)
    private GenderType sexe = GenderType.NON_PRECISE;

    @Column(name = "numero_secu", nullable = false, unique = true, length = 15)
    private String numeroSecu;

    // ===== CONTACT CENTRALISÉ =====
    @Column(name = "email", nullable = false, unique = true)
    private String email;

    @Column(name = "telephone", nullable = false, unique = true, length = 20)
    private String telephone;

    // ===== ADRESSE CENTRALISÉE =====
    @Column(name = "adresse_ligne1", nullable = false)
    private String adresseLigne1;

    @Column(name = "adresse_ligne2")
    private String adresseLigne2;

    @Column(name = "code_postal", nullable = false, length = 10)
    private String codePostal;

    @Column(name = "ville", nullable = false, length = 100)
    private String ville;

    @Column(name = "departement", length = 100)
    private String departement;

    @Column(name = "region", length = 100)
    private String region;

    @Column(name = "pays", nullable = false, length = 100)
    private String pays = "France";

    @Column(name = "latitude", columnDefinition = "DECIMAL(10,8)")
    private BigDecimal latitude;

    @Column(name = "longitude", columnDefinition = "DECIMAL(11,8)")
    private BigDecimal longitude;

    @Column(name = "specificity_ids", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    @Builder.Default
    private List<String> specificityIds = new ArrayList<>();

    @Column(name = "commentaire_patient", columnDefinition = "TEXT")
    private String commentairePatient;

    // ===== PRÉFÉRENCES COMMUNICATION =====
    @Enumerated(EnumType.STRING)
    @Column(name = "methode_livraison_preferee", columnDefinition = "lims_patient.delivery_method")
    private DeliveryMethod methodeLivraisonPreferee = DeliveryMethod.EMAIL;

    @Enumerated(EnumType.STRING)
    @Column(name = "preference_notification", columnDefinition = "lims_patient.notification_preference")
    private NotificationPreference preferenceNotification = NotificationPreference.TOUS;

    @Column(name = "langue_preferee", length = 5)
    private String languePreferee = "fr-FR";

    // ===== PRÉFÉRENCES NOTIFICATIONS =====
    @Column(name = "notifications_resultats")
    private Boolean notificationsResultats = true;

    @Column(name = "notifications_rdv")
    private Boolean notificationsRdv = true;

    @Column(name = "notifications_rappels")
    private Boolean notificationsRappels = true;

    // ===== DONNÉES MÉDICALES =====
    @Column(name = "medecin_traitant")
    private String medecinTraitant;

    @Column(name = "allergies_connues", columnDefinition = "TEXT")
    private String allergiesConnues;

    @Column(name = "antecedents_medicaux", columnDefinition = "TEXT")
    private String antecedentsMedicaux;

    // ===== CONSENTEMENTS RGPD =====
    @Column(name = "consentement_creation_compte", nullable = false)
    private Boolean consentementCreationCompte = false;

    @Column(name = "consentement_sms", nullable = false)
    private Boolean consentementSms = false;

    @Column(name = "consentement_email", nullable = false)
    private Boolean consentementEmail = false;

    @Column(name = "date_consentement")
    private LocalDateTime dateConsentement;

    // ===== MÉTADONNÉES SYSTÈME =====
    @Enumerated(EnumType.STRING)
    @Column(name = "statut", nullable = false)
    private PatientStatus statut = PatientStatus.ACTIF;

    @CreatedDate
    @Column(name = "date_creation", nullable = false, updatable = false)
    private LocalDateTime dateCreation;

    @LastModifiedDate
    @Column(name = "date_modification")
    private LocalDateTime dateModification;

    @CreatedBy
    @Column(name = "cree_par", nullable = false, updatable = false, length = 100)
    private String creePar;

    @LastModifiedBy
    @Column(name = "modifie_par", length = 100)
    private String modifiePar;

    @Column(name = "date_suppression")
    private LocalDateTime dateSuppression; // Soft delete


    // ===== MÉTHODES UTILITAIRES =====

    /**
     * Vérifie si le patient est actif (non supprimé)
     */
    public boolean isActive() {
        return dateSuppression == null && statut == PatientStatus.ACTIF;
    }

    /**
     * Obtient le numéro de sécurité sociale masqué
     */
    public String getNumeroSecuMasque() {
        if (numeroSecu == null || numeroSecu.length() < 15) {
            return "***************";
        }
        return numeroSecu.substring(0, 1) + " " +
                "**" + " " +
                "**" + " " +
                "***" + " " +
                "***" + " " +
                numeroSecu.substring(13);
    }

    /**
     * Obtient l'adresse complète formatée
     */
    public String getAdresseComplete() {
        StringBuilder sb = new StringBuilder();
        sb.append(adresseLigne1);
        if (adresseLigne2 != null && !adresseLigne2.trim().isEmpty()) {
            sb.append(", ").append(adresseLigne2);
        }
        sb.append(", ").append(codePostal).append(" ").append(ville);
        if (!pays.equals("France")) {
            sb.append(", ").append(pays);
        }
        return sb.toString();
    }

    /**
     * Obtient le nom complet du patient
     */
    public String getNomComplet() {
        return prenom + " " + nom;
    }

    /**
     * Calcule l'âge du patient
     */
    public int getAge() {
        if (dateNaissance == null) {
            return 0;
        }
        return LocalDate.now().getYear() - dateNaissance.getYear();
    }

    /**
     * Vérifie si le patient a donné son consentement pour les notifications
     */
    public boolean hasNotificationConsent() {
        return consentementEmail || consentementSms;
    }

    /**
     * Vérifie si le patient accepte les notifications d'un type donné
     */
    public boolean acceptsNotification(String type) {
        return switch (type.toLowerCase()) {
            case "resultats" -> notificationsResultats != null && notificationsResultats;
            case "rdv" -> notificationsRdv != null && notificationsRdv;
            case "rappels" -> notificationsRappels != null && notificationsRappels;
            default -> false;
        };
    }

    public void setCreepar(String creepar) {
        this.creePar = creepar;
    }

    // Méthodes helper pour les spécificités
    public void addSpecificity(String specificityId) {
        if (this.specificityIds == null) {
            this.specificityIds = new ArrayList<>();
        }
        if (!this.specificityIds.contains(specificityId)) {
            this.specificityIds.add(specificityId);
        }
    }

    public void removeSpecificity(String specificityId) {
        if (this.specificityIds != null) {
            this.specificityIds.remove(specificityId);
        }
    }

    public boolean hasSpecificities() {
        return this.specificityIds != null && !this.specificityIds.isEmpty();
    }

    public int getSpecificitiesCount() {
        return this.specificityIds != null ? this.specificityIds.size() : 0;
    }
}