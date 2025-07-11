package com.lims.patient.specification;

import com.lims.patient.entity.Patient;
import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.PatientStatus;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Predicate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.util.StringUtils;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

/**
 * Spécifications JPA complètes pour les requêtes de recherche de patients
 * Version adaptée avec support du nomComplet
 */
@Slf4j
public class PatientSpecifications {

    // ===== SPÉCIFICATIONS DE BASE =====

    /**
     * Specification de base : patient non supprimé
     */
    public static Specification<Patient> notDeleted() {
        return (root, query, criteriaBuilder) ->
                criteriaBuilder.isNull(root.get("dateSuppression"));
    }

    // ===== SPÉCIFICATIONS POUR NOM COMPLET =====

    /**
     * Recherche par nom complet - version simple
     */
    public static Specification<Patient> nomCompletContains(String nomComplet) {
        return (root, query, criteriaBuilder) -> {
            if (!StringUtils.hasText(nomComplet)) {
                return criteriaBuilder.conjunction();
            }

            String searchValue = "%" + nomComplet.toLowerCase() + "%";

            // Créer une expression concaténée : nom + " " + prenom
            Expression<String> nomCompletExpression = criteriaBuilder.concat(
                    criteriaBuilder.lower(root.get("nom")),
                    criteriaBuilder.concat(" ", criteriaBuilder.lower(root.get("prenom")))
            );

            // Aussi créer l'expression inverse : prenom + " " + nom
            Expression<String> prenomNomExpression = criteriaBuilder.concat(
                    criteriaBuilder.lower(root.get("prenom")),
                    criteriaBuilder.concat(" ", criteriaBuilder.lower(root.get("nom")))
            );

            // Chercher dans les deux sens
            Predicate nomPrenomMatch = criteriaBuilder.like(nomCompletExpression, searchValue);
            Predicate prenomNomMatch = criteriaBuilder.like(prenomNomExpression, searchValue);

            // Aussi chercher dans nom seul et prénom seul
            Predicate nomSeulMatch = criteriaBuilder.like(
                    criteriaBuilder.lower(root.get("nom")), searchValue);
            Predicate prenomSeulMatch = criteriaBuilder.like(
                    criteriaBuilder.lower(root.get("prenom")), searchValue);

            return criteriaBuilder.or(nomPrenomMatch, prenomNomMatch, nomSeulMatch, prenomSeulMatch);
        };
    }

    /**
     * Recherche avancée par nom complet avec mots-clés multiples
     */
    public static Specification<Patient> nomCompletAdvanced(String nomComplet) {
        return (root, query, criteriaBuilder) -> {
            if (!StringUtils.hasText(nomComplet)) {
                return criteriaBuilder.conjunction();
            }

            String[] keywords = nomComplet.trim().toLowerCase().split("\\s+");

            if (keywords.length == 1) {
                // Un seul mot : recherche simple
                return nomCompletContains(nomComplet).toPredicate(root, query, criteriaBuilder);
            }

            // Plusieurs mots : chaque mot doit être trouvé dans nom OU prénom
            List<Predicate> keywordPredicates = new ArrayList<>();

            for (String keyword : keywords) {
                String searchValue = "%" + keyword + "%";

                Predicate nomMatch = criteriaBuilder.like(
                        criteriaBuilder.lower(root.get("nom")), searchValue);
                Predicate prenomMatch = criteriaBuilder.like(
                        criteriaBuilder.lower(root.get("prenom")), searchValue);

                keywordPredicates.add(criteriaBuilder.or(nomMatch, prenomMatch));
            }

            // Tous les mots-clés doivent être trouvés (AND)
            return criteriaBuilder.and(keywordPredicates.toArray(new Predicate[0]));
        };
    }

    // ===== SPÉCIFICATIONS INDIVIDUELLES =====

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
     * Recherche par téléphone (recherche partielle avec nettoyage des caractères)
     */
    public static Specification<Patient> hasTelephone(String telephone) {
        return (root, query, criteriaBuilder) -> {
            if (telephone == null || telephone.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }

            // Nettoyer le numéro de recherche
            String cleanSearchPhone = telephone.replaceAll("[^0-9+]", "");
            String searchTerm = "%" + cleanSearchPhone + "%";

            // Recherche dans le téléphone nettoyé
            return criteriaBuilder.like(
                    criteriaBuilder.function("REGEXP_REPLACE", String.class,
                            root.get("telephone"),
                            criteriaBuilder.literal("[^0-9+]"),
                            criteriaBuilder.literal("")),
                    searchTerm
            );
        };
    }

    /**
     * Recherche par ville (recherche partielle, insensible à la casse)
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
     * Recherche par numéro de sécurité sociale (égalité exacte)
     */
    public static Specification<Patient> hasNumeroSecu(String numeroSecu) {
        return (root, query, criteriaBuilder) -> {
            if (numeroSecu == null || numeroSecu.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }
            return criteriaBuilder.equal(root.get("numeroSecu"), numeroSecu.trim());
        };
    }

    // ===== SPÉCIFICATIONS COMPOSÉES =====

    /**
     * Patients actifs (non supprimés + statut actif)
     */
    public static Specification<Patient> active() {
        return (root, query, criteriaBuilder) ->
                criteriaBuilder.and(
                        criteriaBuilder.isNull(root.get("dateSuppression")),
                        criteriaBuilder.equal(root.get("statut"), PatientStatus.ACTIF)
                );
    }

    /**
     * Recherche générale multi-critères (version legacy pour compatibilité)
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

    // ===== SPÉCIFICATIONS UTILITAIRES =====

    /**
     * Recherche par tranche d'âge
     */
    public static Specification<Patient> ageEntre(int ageMin, int ageMax) {
        return (root, query, criteriaBuilder) -> {
            LocalDate now = LocalDate.now();
            LocalDate dateMaxNaissance = now.minusYears(ageMin);
            LocalDate dateMinNaissance = now.minusYears(ageMax + 1);

            return criteriaBuilder.between(
                    root.get("dateNaissance"),
                    dateMinNaissance,
                    dateMaxNaissance
            );
        };
    }

    /**
     * Patients créés récemment (derniers X jours)
     */
    public static Specification<Patient> creesDepuis(int jours) {
        return (root, query, criteriaBuilder) -> {
            LocalDate dateLimit = LocalDate.now().minusDays(jours);
            return criteriaBuilder.greaterThanOrEqualTo(
                    criteriaBuilder.function("DATE", LocalDate.class, root.get("dateCreation")),
                    dateLimit
            );
        };
    }

    /**
     * Recherche par département (basée sur le code postal)
     */
    public static Specification<Patient> dansLeDepartement(String codeDepartement) {
        return (root, query, criteriaBuilder) -> {
            if (codeDepartement == null || codeDepartement.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }

            String pattern = codeDepartement.trim() + "%";
            return criteriaBuilder.like(root.get("codePostal"), pattern);
        };
    }
}