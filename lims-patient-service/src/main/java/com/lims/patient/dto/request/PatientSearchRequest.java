package com.lims.patient.dto.request;

import com.lims.patient.enums.PatientStatus;
import jakarta.validation.constraints.*;
import lombok.Builder;

import java.time.LocalDate;
import java.util.List;

/**
 * DTO pour la recherche de patients - Adapté à l'interface frontend
 *
 * Critères de recherche principaux (au moins un obligatoire) :
 * - Numéro de sécurité sociale
 * - Nom complet (nom + prénom)
 * - Date de naissance
 * - Téléphone
 * - Email
 */
@Builder
public record PatientSearchRequest(

        // ============================================
        // CRITÈRES DE RECHERCHE PRINCIPAUX
        // ============================================

        /**
         * Numéro de sécurité sociale (complet ou partiel)
         * Format: 1234567890123 (13 chiffres)
         */
        @Pattern(regexp = "^[0-9]{3,15}$", message = "Le NIR doit contenir entre 3 et 15 chiffres")
        String numeroSecuSociale,

        /**
         * Nom complet (nom et/ou prénom)
         * Recherche flexible sur les deux champs
         */
        @Size(max = 200, message = "Le nom complet ne peut pas dépasser 200 caractères")
        String nomComplet,

        /**
         * Date de naissance exacte
         */
        LocalDate dateNaissance,

        /**
         * Numéro de téléphone (avec ou sans espaces/points)
         * Formats acceptés: 0123456789, 01 23 45 67 89, +33123456789
         */
        @Pattern(regexp = "^[\\+]?[0-9\\s\\.\\-]{8,15}$", message = "Format de téléphone invalide")
        String telephone,

        /**
         * Adresse email
         */
        @Email(message = "Format d'email invalide")
        String email,

        // ============================================
        // FILTRES AVANCÉS (OPTIONNELS)
        // ============================================

        /**
         * Ville de résidence (filtre additionnel)
         */
        @Size(max = 100)
        String ville,

        /**
         * Code postal (filtre additionnel)
         */
        @Pattern(regexp = "^[0-9]{5}$", message = "Le code postal doit contenir 5 chiffres")
        String codePostal,

        /**
         * Filtres par statut des patients
         */
        List<PatientStatus> statuts,

        /**
         * Filtres par période de création
         */
        LocalDate dateCreationDebut,
        LocalDate dateCreationFin,

        /**
         * Filtres par tranche d'âge
         */
        @Min(value = 0, message = "L'âge minimum doit être positif")
        @Max(value = 120, message = "L'âge maximum ne peut pas dépasser 120")
        Integer ageMinimum,

        @Min(value = 0, message = "L'âge minimum doit être positif")
        @Max(value = 120, message = "L'âge maximum ne peut pas dépasser 120")
        Integer ageMaximum,

        /**
         * Uniquement les patients avec assurance active
         */
        Boolean avecAssuranceActive,

        /**
         * Uniquement les patients avec ordonnance en cours
         */
        Boolean avecOrdonnanceEnCours,

        /**
         * Filtre par utilisateur créateur
         */
        String creePar,

        // ============================================
        // PAGINATION ET TRI
        // ============================================

        /**
         * Numéro de page (0-based)
         */
        @Min(value = 0, message = "Le numéro de page doit être positif")
        Integer page,

        /**
         * Taille de la page
         */
        @Min(value = 1, message = "La taille de page doit être au minimum 1")
        @Max(value = 100, message = "La taille de page ne peut pas dépasser 100")
        Integer size,

        /**
         * Critère de tri
         * Valeurs possibles: nom,asc|desc, prenom,asc|desc, dateNaissance,asc|desc, dateCreation,asc|desc
         */
        @Pattern(regexp = "^(nom|prenom|dateNaissance|dateCreation)(,(asc|desc))?$",
                message = "Format de tri invalide")
        String sort
) {

        /**
         * Valide qu'au moins un critère de recherche principal est fourni
         */
        public boolean hasValidSearchCriteria() {
                return (numeroSecuSociale != null && !numeroSecuSociale.trim().isEmpty()) ||
                        (nomComplet != null && !nomComplet.trim().isEmpty()) ||
                        (dateNaissance != null) ||
                        (telephone != null && !telephone.trim().isEmpty()) ||
                        (email != null && !email.trim().isEmpty());
        }

        /**
         * Retourne une version nettoyée du numéro de téléphone
         */
        public String getTelephoneClean() {
                if (telephone == null) return null;
                return telephone.replaceAll("[^0-9+]", "");
        }

        /**
         * Retourne une version nettoyée du NIR
         */
        public String getNumeroSecuSocialeClean() {
                if (numeroSecuSociale == null) return null;
                return numeroSecuSociale.replaceAll("[^0-9]", "");
        }

        /**
         * Sépare le nom complet en mots individuels pour la recherche
         */
        public String[] getNomCompletTokens() {
                if (nomComplet == null || nomComplet.trim().isEmpty()) {
                        return new String[0];
                }
                return nomComplet.trim().toLowerCase().split("\\s+");
        }

        /**
         * Retourne les valeurs par défaut pour la pagination
         */
        public int getPageOrDefault() {
                return page != null ? page : 0;
        }

        public int getSizeOrDefault() {
                return size != null ? size : 20;
        }

        public String getSortOrDefault() {
                return sort != null ? sort : "nom,asc";
        }
}