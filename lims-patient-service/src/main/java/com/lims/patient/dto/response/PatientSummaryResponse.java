package com.lims.patient.dto.response;

import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.PatientStatus;
import lombok.Builder;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * DTO résumé pour les listes de patients
 */
@Builder
public record PatientSummaryResponse(
        String id,
        String nom,
        String prenom,
        LocalDate dateNaissance,
        GenderType sexe,
        String numeroSecuMasque, // XXX XX XX XXX XXX XX (masqué)
        String telephonePrincipal,
        String emailPrincipal,
        String villePrincipale,
        PatientStatus statut,
        Boolean aAssuranceActive,
        Boolean aOrdonnanceEnCours,
        LocalDateTime dateCreation
) {}
