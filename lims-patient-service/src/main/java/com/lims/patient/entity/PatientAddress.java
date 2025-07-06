package com.lims.patient.entity;

import com.lims.patient.enums.AddressType;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entité Adresse
 */
@Entity
@Table(name = "patient_addresses", schema = "lims_patient")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PatientAddress {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "patient_id", nullable = false)
    private Patient patient;

    @Enumerated(EnumType.STRING)
    @Column(name = "type_adresse", nullable = false)
    private AddressType typeAdresse;

    @Column(name = "ligne1", nullable = false)
    private String ligne1;

    @Column(name = "ligne2")
    private String ligne2;

    @Column(name = "code_postal", nullable = false, length = 10)
    private String codePostal;

    @Column(name = "ville", nullable = false, length = 100)
    private String ville;

    @Column(name = "departement", length = 100)
    private String departement;

    @Column(name = "region", length = 100)
    private String region;

    @Column(name = "pays", nullable = false, length = 50)
    private String pays = "France";

    @Column(name = "latitude", columnDefinition = "DECIMAL(10,8)")
    private BigDecimal latitude;

    @Column(name = "longitude", columnDefinition = "DECIMAL(11,8)")
    private BigDecimal longitude;

    @Column(name = "est_principale", nullable = false)
    private Boolean estPrincipale = false;

    @Column(name = "est_valide", nullable = false)
    private Boolean estValide = false;

    @Column(name = "date_validation")
    private LocalDateTime dateValidation;

    @CreatedDate
    @Column(name = "date_creation", nullable = false, updatable = false)
    private LocalDateTime dateCreation;

    @LastModifiedDate
    @Column(name = "date_modification")
    private LocalDateTime dateModification;

    /**
     * Retourne l'adresse formatée
     */
    public String getAdresseComplete() {
        StringBuilder sb = new StringBuilder();
        sb.append(ligne1);
        if (ligne2 != null && !ligne2.trim().isEmpty()) {
            sb.append(", ").append(ligne2);
        }
        sb.append(", ").append(codePostal).append(" ").append(ville);
        if (!pays.equals("France")) {
            sb.append(", ").append(pays);
        }
        return sb.toString();
    }
}
