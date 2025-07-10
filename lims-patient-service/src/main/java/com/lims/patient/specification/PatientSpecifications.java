package com.lims.patient.specification;

import com.lims.patient.entity.Patient;
import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.PatientStatus;
import org.springframework.data.jpa.domain.Specification;

import java.time.LocalDate;

/**
 * Specifications pour construire dynamiquement les requêtes Patient
 */
public class PatientSpecifications {

    /**
     * Specification de base : patient non supprimé
     */
    public static Specification<Patient> notDeleted() {
        return (root, query, criteriaBuilder) ->
                criteriaBuilder.isNull(root.get("dateSuppression"));
    }

    /**
     * Recherche par nom (insensible à la casse, recherche partielle)
     */
    public static Specification<Patient> hasNom(String nom) {
        return (root, query, criteriaBuilder) -> {
            if (nom == null || nom.trim().isEmpty()) {
                return criteriaBuilder.conjunction(); // Toujours vrai
            }
            String searchTerm = "%" + nom.toLowerCase().trim() + "%";
            return criteriaBuilder.like(
                    criteriaBuilder.lower(root.get("nom")),
                    searchTerm
            );
        };
    }

    /**
     * Recherche par prénom (insensible à la casse, recherche partielle)
     */
    public static Specification<Patient> hasPrenom(String prenom) {
        return (root, query, criteriaBuilder) -> {
            if (prenom == null || prenom.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }
            String searchTerm = "%" + prenom.toLowerCase().trim() + "%";
            return criteriaBuilder.like(
                    criteriaBuilder.lower(root.get("prenom")),
                    searchTerm
            );
        };
    }

    /**
     * Recherche par email (égalité exacte, insensible à la casse)
     */
    public static Specification<Patient> hasEmail(String email) {
        return (root, query, criteriaBuilder) -> {
            if (email == null || email.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }
            return criteriaBuilder.equal(
                    criteriaBuilder.lower(root.get("email")),
                    email.toLowerCase().trim()
            );
        };
    }

    /**
     * Recherche par email partielle (recherche partielle, insensible à la casse)
     */
    public static Specification<Patient> hasEmailContaining(String email) {
        return (root, query, criteriaBuilder) -> {
            if (email == null || email.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }
            String searchTerm = "%" + email.toLowerCase().trim() + "%";
            return criteriaBuilder.like(
                    criteriaBuilder.lower(root.get("email")),
                    searchTerm
            );
        };
    }

    /**
     * Recherche par téléphone (recherche partielle)
     */
    public static Specification<Patient> hasTelephone(String telephone) {
        return (root, query, criteriaBuilder) -> {
            if (telephone == null || telephone.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }
            String searchTerm = "%" + telephone.trim() + "%";
            return criteriaBuilder.like(root.get("telephone"), searchTerm);
        };
    }

    /**
     * Recherche par ville (insensible à la casse, recherche partielle)
     */
    public static Specification<Patient> hasVille(String ville) {
        return (root, query, criteriaBuilder) -> {
            if (ville == null || ville.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }
            String searchTerm = "%" + ville.toLowerCase().trim() + "%";
            return criteriaBuilder.like(
                    criteriaBuilder.lower(root.get("ville")),
                    searchTerm
            );
        };
    }

    /**
     * Recherche par code postal (égalité exacte)
     */
    public static Specification<Patient> hasCodePostal(String codePostal) {
        return (root, query, criteriaBuilder) -> {
            if (codePostal == null || codePostal.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }
            return criteriaBuilder.equal(root.get("codePostal"), codePostal.trim());
        };
    }

    /**
     * Recherche par date de naissance (égalité exacte)
     */
    public static Specification<Patient> hasDateNaissance(LocalDate dateNaissance) {
        return (root, query, criteriaBuilder) -> {
            if (dateNaissance == null) {
                return criteriaBuilder.conjunction();
            }
            return criteriaBuilder.equal(root.get("dateNaissance"), dateNaissance);
        };
    }

    /**
     * Recherche par sexe
     */
    public static Specification<Patient> hasSexe(GenderType sexe) {
        return (root, query, criteriaBuilder) -> {
            if (sexe == null) {
                return criteriaBuilder.conjunction();
            }
            return criteriaBuilder.equal(root.get("sexe"), sexe);
        };
    }

    /**
     * Recherche par statut
     */
    public static Specification<Patient> hasStatut(PatientStatus statut) {
        return (root, query, criteriaBuilder) -> {
            if (statut == null) {
                return criteriaBuilder.conjunction();
            }
            return criteriaBuilder.equal(root.get("statut"), statut);
        };
    }

    /**
     * Recherche par numéro de sécurité sociale
     */
    public static Specification<Patient> hasNumeroSecu(String numeroSecu) {
        return (root, query, criteriaBuilder) -> {
            if (numeroSecu == null || numeroSecu.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }
            return criteriaBuilder.equal(root.get("numeroSecu"), numeroSecu.trim());
        };
    }

    /**
     * Combine toutes les specifications pour la recherche multicritères
     */
    public static Specification<Patient> searchCriteria(
            String nom,
            String prenom,
            String numeroSecu,
            String email,
            String telephone,
            String ville,
            String codePostal,
            LocalDate dateNaissance,
            GenderType sexe,
            PatientStatus statut,
            boolean emailExactMatch) {

        return Specification.where(notDeleted())
                .and(hasNom(nom))
                .and(hasPrenom(prenom))
                .and(hasNumeroSecu(numeroSecu))
                .and(emailExactMatch ? hasEmail(email) : hasEmailContaining(email))
                .and(hasTelephone(telephone))
                .and(hasVille(ville))
                .and(hasCodePostal(codePostal))
                .and(hasDateNaissance(dateNaissance))
                .and(hasSexe(sexe))
                .and(hasStatut(statut));
    }
}