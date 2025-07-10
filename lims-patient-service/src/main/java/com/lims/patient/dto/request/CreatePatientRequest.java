// ============================================
// DTOs pour la création de patients (version centralisée)
// ============================================

package com.lims.patient.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
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

        @Valid @NotNull
        ConsentRequest consent,

        String createdBy // ID du staff qui crée le patient
) {}