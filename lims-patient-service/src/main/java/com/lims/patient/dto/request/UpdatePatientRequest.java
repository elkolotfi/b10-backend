package com.lims.patient.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;
import lombok.Builder;

import java.util.List;

/**
 * DTO pour la mise à jour partielle d'un patient via PATCH
 * Tous les champs sont optionnels pour permettre une mise à jour atomique
 */
@Builder
public record UpdatePatientRequest(
        @Valid
        PersonalInfoRequest personalInfo,

        @Valid
        ContactInfoRequest contactInfo,

        @Valid
        List<InsuranceRequest> insurances,

        @Valid
        PatientSpecificitiesRequest specificities,

        @Valid
        ConsentRequest consent,

        @Size(max = 2000, message = "Le commentaire ne peut pas dépasser 2000 caractères")
        String commentairePatient
) {}