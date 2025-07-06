package com.lims.patient.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entité Email
 */
@Entity
@Table(name = "patient_emails", schema = "lims_patient")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PatientEmail {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "patient_id", nullable = false)
    private Patient patient;

    @Column(name = "adresse_email", nullable = false, unique = true)
    private String adresseEmail;

    @Column(name = "est_principal", nullable = false)
    private Boolean estPrincipal = false;

    @Column(name = "est_valide", nullable = false)
    private Boolean estValide = false;

    @Column(name = "date_validation")
    private LocalDateTime dateValidation;

    // Préférences notifications
    @Column(name = "notifications_resultats")
    private Boolean notificationsResultats = true;

    @Column(name = "notifications_rdv")
    private Boolean notificationsRdv = true;

    @Column(name = "notifications_rappels")
    private Boolean notificationsRappels = true;

    @CreatedDate
    @Column(name = "date_creation", nullable = false, updatable = false)
    private LocalDateTime dateCreation;

    @LastModifiedDate
    @Column(name = "date_modification")
    private LocalDateTime dateModification;
}
