package com.lims.patient.dto.request;

import lombok.Builder;

import java.util.List;

/**
 * DTO pour la mise à jour d'un patient
 */
@Builder
public record UpdatePatientRequest(
        PersonalInfoUpdateRequest personalInfo,
        ContactInfoUpdateRequest contactInfo,
        List<InsuranceRequest> insurances,
        ConsentUpdateRequest consent
) {}
