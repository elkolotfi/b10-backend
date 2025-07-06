package com.lims.patient.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;

import java.util.List;

/**
 * DTO principal pour la création d'un patient
 * Structure organisée par domaines fonctionnels
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
