package com.lims.patient.dto.request;

import com.lims.patient.enums.InsuranceType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;

import java.math.BigDecimal;
import java.time.LocalDate;

/**
 * DTO pour la création/modification d'une assurance patient.
 * RÈGLE MÉTIER : Le document justificatif est OBLIGATOIRE.
 */
@Schema(description = "Données pour créer ou modifier une assurance/mutuelle patient")
public record InsuranceRequest(

        @NotNull(message = "Le type d'assurance est obligatoire")
        @Schema(description = "Type d'assurance", example = "COMPLEMENTAIRE", required = true)
        InsuranceType typeAssurance,

        @NotBlank(message = "Le nom de l'organisme est obligatoire")
        @Size(max = 255, message = "Le nom de l'organisme ne peut pas dépasser 255 caractères")
        @Schema(description = "Nom de l'organisme d'assurance", example = "Harmonie Mutuelle", required = true)
        String nomOrganisme,

        @NotBlank(message = "Le numéro d'adhérent est obligatoire")
        @Size(min = 5, max = 100, message = "Le numéro d'adhérent doit contenir entre 5 et 100 caractères")
        @Schema(description = "Numéro d'adhérent ou de contrat", example = "MUT123456789", required = true)
        String numeroAdherent,

        @NotNull(message = "La date de début est obligatoire")
        @Schema(description = "Date de début de validité", example = "2024-01-01", required = true)
        LocalDate dateDebut,

        @Schema(description = "Date de fin de validité (optionnelle)", example = "2024-12-31")
        LocalDate dateFin,

        @Schema(description = "Tiers payant autorisé", example = "true", defaultValue = "false")
        Boolean tiersPayantAutorise,

        @DecimalMin(value = "0.00", message = "Le pourcentage doit être positif")
        @DecimalMax(value = "100.00", message = "Le pourcentage ne peut pas dépasser 100%")
        @Digits(integer = 3, fraction = 2, message = "Format invalide pour le pourcentage")
        @Schema(description = "Pourcentage de prise en charge", example = "70.00")
        BigDecimal pourcentagePriseCharge,

        @NotBlank(message = "Le document justificatif est obligatoire - Veuillez uploader la carte de mutuelle")
        @Size(max = 500, message = "La référence du document ne peut pas dépasser 500 caractères")
        @Schema(description = "Référence du document justificatif sur MinIO (OBLIGATOIRE)",
                example = "insurance-docs/patient-123/carte-mutuelle-2024.pdf", required = true)
        String referenceDocument

) {

        /**
         * Validation personnalisée des dates.
         */
        public boolean isDateRangeValid() {
                return dateFin == null || !dateFin.isBefore(dateDebut);
        }

        /**
         * Vérifie si l'assurance est actuellement valide.
         */
        public boolean isCurrentlyValid() {
                LocalDate now = LocalDate.now();
                return !dateDebut.isAfter(now) && (dateFin == null || !dateFin.isBefore(now));
        }
}