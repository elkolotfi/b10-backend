package com.lims.patient.entity;

import com.lims.patient.enums.ContactType;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entité Contact téléphonique
 */
@Entity
@Table(name = "patient_contacts", schema = "lims_patient")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PatientContact {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "patient_id", nullable = false)
    private Patient patient;

    @Enumerated(EnumType.STRING)
    @Column(name = "type_contact", nullable = false)
    private ContactType typeContact;

    @Column(name = "numero_telephone", nullable = false, length = 20)
    private String numeroTelephone;

    @Column(name = "indicatif_pays", length = 5)
    private String indicatifPays = "+33";

    @Column(name = "extension", length = 10)
    private String extension;

    @Column(name = "est_principal", nullable = false)
    private Boolean estPrincipal = false;

    @Column(name = "est_valide", nullable = false)
    private Boolean estValide = false;

    @Column(name = "date_validation")
    private LocalDateTime dateValidation;

    // Contact d'urgence
    @Column(name = "nom_contact_urgence", length = 100)
    private String nomContactUrgence;

    @Column(name = "relation_contact", length = 50)
    private String relationContact;

    @CreatedDate
    @Column(name = "date_creation", nullable = false, updatable = false)
    private LocalDateTime dateCreation;

    @LastModifiedDate
    @Column(name = "date_modification")
    private LocalDateTime dateModification;
}
