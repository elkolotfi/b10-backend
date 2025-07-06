package com.lims.patient.entity;

import com.lims.patient.enums.DeliveryMethod;
import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.NotificationPreference;
import com.lims.patient.enums.PatientStatus;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Entité principale Patient
 * Contient les données civiles obligatoires et préférences
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

    // ===== PRÉFÉRENCES COMMUNICATION =====
    @Enumerated(EnumType.STRING)
    @Column(name = "methode_livraison_preferee")
    private DeliveryMethod methodeLivraisonPreferee = DeliveryMethod.EMAIL;

    @Enumerated(EnumType.STRING)
    @Column(name = "preference_notification")
    private NotificationPreference preferenceNotification = NotificationPreference.TOUS;

    @Column(name = "langue_preferee", length = 5)
    private String languePreferee = "fr-FR";

    // ===== DONNÉES MÉDICALES FACULTATIVES =====
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

    // ===== RELATIONS =====
    @OneToMany(mappedBy = "patient", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @Builder.Default
    private List<PatientContact> contacts = new ArrayList<>();

    @OneToMany(mappedBy = "patient", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @Builder.Default
    private List<PatientAddress> adresses = new ArrayList<>();

    @OneToMany(mappedBy = "patient", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @Builder.Default
    private List<PatientEmail> emails = new ArrayList<>();

    @OneToMany(mappedBy = "patient", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @Builder.Default
    private List<PatientAssurance> assurances = new ArrayList<>();

    @OneToMany(mappedBy = "patient", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @Builder.Default
    private List<Ordonnance> ordonnances = new ArrayList<>();

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
     * Ajoute un contact téléphonique
     */
    public void addContact(PatientContact contact) {
        contact.setPatient(this);
        this.contacts.add(contact);
    }

    /**
     * Ajoute une adresse
     */
    public void addAdresse(PatientAddress adresse) {
        adresse.setPatient(this);
        this.adresses.add(adresse);
    }

    /**
     * Ajoute un email
     */
    public void addEmail(PatientEmail email) {
        email.setPatient(this);
        this.emails.add(email);
    }

    /**
     * Ajoute une assurance
     */
    public void addAssurance(PatientAssurance assurance) {
        assurance.setPatient(this);
        this.assurances.add(assurance);
    }
}
