package com.lims.patient.dto.response;

import com.lims.patient.enums.InsuranceType;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * DTO de réponse pour les assurances patients.
 */
@Builder
@Schema(description = "Informations complètes d'une assurance/mutuelle patient")
public record PatientInsuranceResponse(

        @Schema(description = "Identifiant unique de l'assurance", example = "123e4567-e89b-12d3-a456-426614174000")
        UUID id,

        @Schema(description = "Identifiant du patient", example = "456e7890-e89b-12d3-a456-426614174001")
        UUID patientId,

        @Schema(description = "Type d'assurance", example = "COMPLEMENTAIRE")
        InsuranceType typeAssurance,

        @Schema(description = "Libellé du type d'assurance", example = "Assurance complémentaire (Mutuelle)")
        String typeAssuranceLibelle,

        @Schema(description = "Nom de l'organisme d'assurance", example = "Harmonie Mutuelle")
        String nomOrganisme,

        @Schema(description = "Numéro d'adhérent", example = "MUT123456789")
        String numeroAdherent,

        @Schema(description = "Date de début de validité", example = "2024-01-01")
        LocalDate dateDebut,

        @Schema(description = "Date de fin de validité", example = "2024-12-31")
        LocalDate dateFin,

        @Schema(description = "Assurance actuellement active", example = "true")
        Boolean estActive,

        @Schema(description = "Tiers payant autorisé", example = "true")
        Boolean tiersPayantAutorise,

        @Schema(description = "Pourcentage de prise en charge", example = "70.00")
        BigDecimal pourcentagePriseCharge,

        @Schema(description = "Référence du document justificatif sur MinIO")
        String referenceDocument,

        @Schema(description = "Date d'upload du document", example = "2024-07-29T10:30:00")
        LocalDateTime dateUploadDocument,

        @Schema(description = "Date de création de l'assurance", example = "2024-07-29T10:30:00")
        LocalDateTime dateCreation,

        @Schema(description = "Date de dernière modification", example = "2024-07-29T10:30:00")
        LocalDateTime dateModification,

        @Schema(description = "Assurance actuellement valide (selon les dates)", example = "true")
        boolean currentlyValid,

        @Schema(description = "Nombre de jours avant expiration (-1 si pas d'expiration)")
        Long daysUntilExpiration

) {

    /**
     * Factory method pour créer une réponse avec calculs automatiques.
     */
    public static PatientInsuranceResponse of(UUID id, UUID patientId, InsuranceType typeAssurance,
                                              String nomOrganisme, String numeroAdherent,
                                              LocalDate dateDebut, LocalDate dateFin,
                                              Boolean estActive, Boolean tiersPayantAutorise,
                                              BigDecimal pourcentagePriseCharge, String referenceDocument,
                                              LocalDateTime dateUploadDocument, LocalDateTime dateCreation,
                                              LocalDateTime dateModification) {

        LocalDate now = LocalDate.now();
        boolean currentlyValid = estActive &&
                !dateDebut.isAfter(now) &&
                (dateFin == null || !dateFin.isBefore(now));

        Long daysUntilExpiration = dateFin != null ?
                java.time.temporal.ChronoUnit.DAYS.between(now, dateFin) : -1L;

        return PatientInsuranceResponse.builder()
                .id(id)
                .patientId(patientId)
                .typeAssurance(typeAssurance)
                .typeAssuranceLibelle(typeAssurance.getLabel())
                .nomOrganisme(nomOrganisme)
                .numeroAdherent(numeroAdherent)
                .dateDebut(dateDebut)
                .dateFin(dateFin)
                .estActive(estActive)
                .tiersPayantAutorise(tiersPayantAutorise)
                .pourcentagePriseCharge(pourcentagePriseCharge)
                .referenceDocument(referenceDocument)
                .dateUploadDocument(dateUploadDocument)
                .dateCreation(dateCreation)
                .dateModification(dateModification)
                .currentlyValid(currentlyValid)
                .daysUntilExpiration(daysUntilExpiration)
                .build();
    }
}