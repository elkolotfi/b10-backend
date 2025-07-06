package com.lims.patient.dto.response;

import com.lims.patient.dto.request.*;
import lombok.Builder;

import java.util.List;

/**
 * DTO complet pour la réponse patient
 */
@Builder
public record PatientResponse(
        String id,
        PersonalInfoResponse personalInfo,
        ContactInfoResponse contactInfo,
        List<InsuranceResponse> insurances,
        List<PrescriptionSummaryResponse> ordonnances,
        ConsentResponse consent,
        MetadataResponse metadata
) {}
