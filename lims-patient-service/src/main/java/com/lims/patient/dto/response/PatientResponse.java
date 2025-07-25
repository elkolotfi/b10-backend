package com.lims.patient.dto.response;

import lombok.Builder;

import java.util.List;

/**
 * DTO de réponse pour un patient complet
 */
@Builder
public record PatientResponse(
        String id,
        PersonalInfoResponse personalInfo,
        ContactInfoResponse contactInfo,
        List<InsuranceResponse> insurances,
        PatientSpecificitiesResponse specificities,
        ConsentResponse consent,
        String commentairePatient
) {}
