package com.lims.patient.dto.request;

import lombok.Builder;

/**
 * DTO pour la modification d'un patient
 * Tous les champs sont optionnels pour permettre les mises à jour partielles
 */
@Builder
public record UpdatePatientRequest(
        PersonalInfoUpdateRequest personalInfo,
        ContactInfoUpdateRequest contactInfo,
        ConsentUpdateRequest consent,
        String modifiedBy
) {}
