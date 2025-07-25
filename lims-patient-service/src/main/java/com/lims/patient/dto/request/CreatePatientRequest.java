// ============================================
// DTOs pour la création de patients (version centralisée)
// ============================================

package com.lims.patient.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Builder;

import java.util.List;

/**
 * DTO principal pour la création d'un patient - Version centralisée
 */
@Builder
public record CreatePatientRequest(
        @Valid @NotNull
        PersonalInfoRequest personalInfo,

        @Valid @NotNull
        ContactInfoRequest contactInfo,

        @Valid
        List<InsuranceRequest> insurances,

        @Valid
        PatientSpecificitiesRequest specificities, // Liste d'IDs seulement

        @Valid @NotNull
        ConsentRequest consent,

        @Size(max = 2000, message = "Le commentaire ne peut pas dépasser 2000 caractères")
        String commentairePatient,

        String createdBy
) {}