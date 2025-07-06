package com.lims.patient.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Pattern;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entité pour l'audit trail des patients (conformité RGPD)
 */
@Entity
@Table(name = "audit_logs", schema = "lims_patient")
@Builder
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class PatientAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "patient_id")
    private UUID patientId;

    @Column(name = "action", nullable = false, length = 100)
    private String action;

    @Column(name = "description", length = 500)
    private String description;

    @Column(name = "table_concernee", length = 100)
    private String tableConcernee;

    @Column(name = "id_enregistrement", length = 100)
    private String idEnregistrement;

    // Qui a effectué l'action
    @Column(name = "effectue_par", nullable = false, length = 100)
    private String performedBy;

    @Column(name = "type_utilisateur", nullable = false, length = 20)
    private String performedByType;

    @Column(name = "realm_utilisateur", length = 50)
    private String realmUtilisateur;

    // Contexte technique
    @Column(name = "adresse_ip", columnDefinition = "INET")
    @Pattern(regexp = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$",
            message = "Format d'adresse IP invalide")
    private String clientIp;

    @Column(name = "user_agent", columnDefinition = "TEXT")
    private String userAgent;

    @Column(name = "session_id", length = 100)
    private String sessionId;

    // Données modifiées (pour audit détaillé)
    @Column(name = "anciennes_valeurs", columnDefinition = "JSONB")
    private String anciennesValeurs;

    @Column(name = "nouvelles_valeurs", columnDefinition = "JSONB")
    private String nouvellesValeurs;

    // Résultat de l'action
    @Column(name = "resultat", nullable = false, length = 20)
    private String result;

    @Column(name = "message_erreur", columnDefinition = "TEXT")
    private String messageErreur;

    @CreatedDate
    @Column(name = "date_action", nullable = false)
    private LocalDateTime dateAction;

    @Column(name = "correlation_id")
    private UUID correlationId;
}