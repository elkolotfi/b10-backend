package com.lims.patient.dto.request;

import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.PatientStatus;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.Builder;

import java.time.LocalDate;

/**
 * DTO pour la recherche de patients
 */
@Builder
public record PatientSearchRequest(
        // Recherche par nom et prénom séparés (ancienne méthode)
        String nom,
        String prenom,

        // Recherche par nom complet (nouvelle méthode)
        String nomComplet,

        String numeroSecu,
        String email,
        String telephone,
        String ville,
        String codePostal,
        LocalDate dateNaissance,
        GenderType sexe,
        PatientStatus statut,

        @Min(0) int page,
        @Min(1) @Max(100) int size,
        String sortBy,
        String sortDirection
) {

    /**
     * Constructeur par défaut avec valeurs par défaut pour pagination
     */
    public PatientSearchRequest {
        if (page < 0) page = 0;
        if (size < 1) size = 10;
        if (size > 100) size = 100;
        if (sortBy == null || sortBy.trim().isEmpty()) sortBy = "dateCreation";
        if (sortDirection == null || (!sortDirection.equalsIgnoreCase("asc") && !sortDirection.equalsIgnoreCase("desc"))) {
            sortDirection = "desc";
        }
    }

    /**
     * Vérifie si la recherche utilise le nom complet
     */
    public boolean isNomCompletSearch() {
        return nomComplet != null && !nomComplet.trim().isEmpty();
    }

    /**
     * Vérifie si la recherche utilise nom/prénom séparés
     */
    public boolean isNomPrenomSearch() {
        return (nom != null && !nom.trim().isEmpty()) ||
                (prenom != null && !prenom.trim().isEmpty());
    }

    /**
     * Retourne les mots-clés du nom complet pour la recherche
     */
    public String[] getNomCompletKeywords() {
        if (!isNomCompletSearch()) {
            return new String[0];
        }

        return nomComplet.trim()
                .toLowerCase()
                .split("\\s+"); // Divise par un ou plusieurs espaces
    }

    /**
     * Normalise le nom complet pour la recherche
     */
    public String getNomCompletNormalized() {
        if (!isNomCompletSearch()) {
            return "";
        }

        return nomComplet.trim()
                .toLowerCase()
                .replaceAll("\\s+", " "); // Remplace les espaces multiples par un seul
    }
}