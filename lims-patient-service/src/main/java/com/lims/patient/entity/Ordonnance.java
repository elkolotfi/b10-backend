package com.lims.patient.entity;

import com.lims.patient.enums.PrescriptionStatus;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Entité Ordonnance
 */
@Entity
@Table(name = "ordonnances", schema = "lims_patient")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Ordonnance {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "patient_id", nullable = false)
    private Patient patient;

    @Column(name = "nom_medecin", nullable = false)
    private String nomMedecin;

    @Column(name = "rpps_medecin", length = 20)
    private String rppsMedecin;

    @Column(name = "date_prescription", nullable = false)
    private LocalDate datePrescription;

    @Enumerated(EnumType.STRING)
    @Column(name = "statut")
    private PrescriptionStatus statut = PrescriptionStatus.EN_ATTENTE;

    @Column(name = "reference_document", length = 500)
    private String referenceDocument; // Clé MinIO

    @Column(name = "texte_extrait", columnDefinition = "TEXT")
    private String texteExtrait;

    @Column(name = "confidence_ocr", precision = 5, scale = 2)
    private BigDecimal confidenceOcr;

    @Column(name = "est_renouvelable", nullable = false)
    private Boolean estRenouvelable = false;

    @Column(name = "renouvelable_jusqu")
    private LocalDate renouvelableJusqu;

    @Column(name = "nombre_renouvellements")
    private Integer nombreRenouvellements = 0;

    @Column(name = "validee_par", length = 100)
    private String valideePar;

    @Column(name = "date_validation")
    private LocalDateTime dateValidation;

    @Column(name = "commentaire_validation", columnDefinition = "TEXT")
    private String commentaireValidation;

    @CreatedDate
    @Column(name = "date_creation", nullable = false, updatable = false)
    private LocalDateTime dateCreation;

    @LastModifiedDate
    @Column(name = "date_modification")
    private LocalDateTime dateModification;

    @Column(name = "date_suppression")
    private LocalDateTime dateSuppression; // Soft delete

    @OneToMany(mappedBy = "ordonnance", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @Builder.Default
    private List<OrdonnanceAnalyse> analyses = new ArrayList<>();

    /**
     * Vérifie si l'ordonnance est encore valide pour renouvellement
     */
    public boolean canBeRenewed() {
        return estRenouvelable &&
                renouvelableJusqu != null &&
                !LocalDate.now().isAfter(renouvelableJusqu) &&
                dateSuppression == null;
    }
}
