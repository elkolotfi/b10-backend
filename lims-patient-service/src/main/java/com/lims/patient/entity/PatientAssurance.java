package com.lims.patient.entity;

import com.lims.patient.enums.InsuranceType;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entité Assurance
 */
@Entity
@Table(name = "patient_assurances", schema = "lims_patient")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PatientAssurance {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "patient_id", nullable = false)
    private Patient patient;

    @Enumerated(EnumType.STRING)
    @Column(name = "type_assurance", nullable = false)
    private InsuranceType typeAssurance;

    @Column(name = "nom_organisme", nullable = false)
    private String nomOrganisme;

    @Column(name = "numero_adherent", nullable = false, length = 100)
    private String numeroAdherent;

    @Column(name = "date_debut", nullable = false)
    private LocalDate dateDebut;

    @Column(name = "date_fin")
    private LocalDate dateFin;

    @Column(name = "est_active", nullable = false)
    private Boolean estActive = true;

    @Column(name = "tiers_payant_autorise")
    private Boolean tiersPayantAutorise = false;

    @Column(name = "pourcentage_prise_charge", columnDefinition = "DECIMAL(5,2)")
    private BigDecimal pourcentagePriseCharge;

    @Column(name = "reference_document", length = 500)
    private String referenceDocument; // Clé MinIO

    @Column(name = "date_upload_document")
    private LocalDateTime dateUploadDocument;

    @CreatedDate
    @Column(name = "date_creation", nullable = false, updatable = false)
    private LocalDateTime dateCreation;

    @LastModifiedDate
    @Column(name = "date_modification")
    private LocalDateTime dateModification;

    /**
     * Vérifie si l'assurance est actuellement valide
     */
    public boolean isCurrentlyValid() {
        LocalDate now = LocalDate.now();
        return estActive &&
                (dateDebut == null || !now.isBefore(dateDebut)) &&
                (dateFin == null || !now.isAfter(dateFin));
    }
}
