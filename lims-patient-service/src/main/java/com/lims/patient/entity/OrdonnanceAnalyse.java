package com.lims.patient.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entité Analyse demandée dans une ordonnance
 */
@Entity
@Table(name = "ordonnance_analyses", schema = "lims_patient")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OrdonnanceAnalyse {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ordonnance_id", nullable = false)
    private Ordonnance ordonnance;

    @Column(name = "code_analyse", nullable = false, length = 20)
    private String codeAnalyse;

    @Column(name = "libelle_analyse", nullable = false)
    private String libelleAnalyse;

    @Column(name = "est_urgent", nullable = false)
    private Boolean estUrgent = false;

    @Column(name = "commentaire", columnDefinition = "TEXT")
    private String commentaire;

    @Column(name = "extrait_automatiquement")
    private Boolean extraitAutomatiquement = false;

    @Column(name = "confidence_extraction", precision = 5, scale = 2)
    private BigDecimal confidenceExtraction;

    @CreatedDate
    @Column(name = "date_creation", nullable = false, updatable = false)
    private LocalDateTime dateCreation;
}
