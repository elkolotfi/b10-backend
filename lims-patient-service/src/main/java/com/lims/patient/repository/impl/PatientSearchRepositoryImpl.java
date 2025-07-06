package com.lims.patient.repository.impl;

import com.lims.patient.dto.request.PatientSearchRequest;
import com.lims.patient.entity.*;
import com.lims.patient.enums.PrescriptionStatus;
import com.lims.patient.repository.PatientSearchRepository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.*;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Implémentation des recherches complexes avec Criteria API
 */
@Repository
@RequiredArgsConstructor
public class PatientSearchRepositoryImpl implements PatientSearchRepository {

    private final EntityManager entityManager;

    @Override
    public Page<Patient> searchPatients(PatientSearchRequest request, Pageable pageable) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<Patient> query = cb.createQuery(Patient.class);
        Root<Patient> patient = query.from(Patient.class);

        // Joins pour les recherches sur les entités liées
        Join<Patient, PatientContact> contactJoin = patient.join("contacts", JoinType.LEFT);
        Join<Patient, PatientAddress> addressJoin = patient.join("adresses", JoinType.LEFT);
        Join<Patient, PatientEmail> emailJoin = patient.join("emails", JoinType.LEFT);
        Join<Patient, PatientAssurance> assuranceJoin = patient.join("assurances", JoinType.LEFT);

        List<Predicate> predicates = new ArrayList<>();

        // Patient non supprimé (toujours appliqué)
        predicates.add(cb.isNull(patient.get("dateSuppression")));

        // ============================================
        // CRITÈRES DE RECHERCHE PRINCIPAUX
        // ============================================

        // 1. Numéro de sécurité sociale
        if (request.numeroSecuSociale() != null && !request.numeroSecuSociale().trim().isEmpty()) {
            String nirClean = request.getNumeroSecuSocialeClean();
            predicates.add(cb.like(patient.get("numeroSecu"), "%" + nirClean + "%"));
        }

        // 2. Nom complet (recherche flexible sur nom ET prénom)
        if (request.nomComplet() != null && !request.nomComplet().trim().isEmpty()) {
            String[] tokens = request.getNomCompletTokens();

            if (tokens.length > 0) {
                List<Predicate> nomPrenomPredicates = new ArrayList<>();

                for (String token : tokens) {
                    if (token.length() >= 2) { // Éviter les termes trop courts
                        Predicate nomMatch = cb.like(cb.lower(patient.get("nom")), "%" + token + "%");
                        Predicate prenomMatch = cb.like(cb.lower(patient.get("prenom")), "%" + token + "%");
                        nomPrenomPredicates.add(cb.or(nomMatch, prenomMatch));
                    }
                }

                if (!nomPrenomPredicates.isEmpty()) {
                    // Tous les tokens doivent matcher (ET logique)
                    predicates.add(cb.and(nomPrenomPredicates.toArray(new Predicate[0])));
                }
            }
        }

        // 3. Date de naissance exacte
        if (request.dateNaissance() != null) {
            predicates.add(cb.equal(patient.get("dateNaissance"), request.dateNaissance()));
        }

        // 4. Téléphone (recherche flexible)
        if (request.telephone() != null && !request.telephone().trim().isEmpty()) {
            String phoneClean = request.getTelephoneClean();

            // Recherche flexible sur le téléphone normalisé
            Predicate phoneMatch = cb.like(
                    cb.function("REPLACE", String.class,
                            cb.function("REPLACE", String.class,
                                    cb.function("REPLACE", String.class, contactJoin.get("numeroTelephone"),
                                            cb.literal(" "), cb.literal("")),
                                    cb.literal("."), cb.literal("")),
                            cb.literal("-"), cb.literal("")),
                    "%" + phoneClean + "%");

            predicates.add(phoneMatch);
        }

        // 5. Email (recherche partielle insensible à la casse)
        if (request.email() != null && !request.email().trim().isEmpty()) {
            predicates.add(cb.like(
                    cb.lower(emailJoin.get("adresseEmail")),
                    "%" + request.email().toLowerCase() + "%"));
        }

        // ============================================
        // FILTRES AVANCÉS OPTIONNELS
        // ============================================

        // Ville
        if (request.ville() != null && !request.ville().trim().isEmpty()) {
            predicates.add(cb.like(
                    cb.lower(addressJoin.get("ville")),
                    "%" + request.ville().toLowerCase() + "%"));
        }

        // Code postal
        if (request.codePostal() != null && !request.codePostal().trim().isEmpty()) {
            predicates.add(cb.equal(addressJoin.get("codePostal"), request.codePostal()));
        }

        // Statuts
        if (request.statuts() != null && !request.statuts().isEmpty()) {
            predicates.add(patient.get("statut").in(request.statuts()));
        }

        // Période de création
        if (request.dateCreationDebut() != null) {
            predicates.add(cb.greaterThanOrEqualTo(
                    patient.get("dateCreation"), request.dateCreationDebut().atStartOfDay()));
        }
        if (request.dateCreationFin() != null) {
            predicates.add(cb.lessThanOrEqualTo(
                    patient.get("dateCreation"), request.dateCreationFin().atTime(23, 59, 59)));
        }

        // Filtre par âge (calculé à partir de la date de naissance)
        if (request.ageMinimum() != null || request.ageMaximum() != null) {
            LocalDate today = LocalDate.now();

            if (request.ageMaximum() != null) {
                LocalDate minDateNaissance = today.minusYears(request.ageMaximum() + 1);
                predicates.add(cb.greaterThan(patient.get("dateNaissance"), minDateNaissance));
            }

            if (request.ageMinimum() != null) {
                LocalDate maxDateNaissance = today.minusYears(request.ageMinimum());
                predicates.add(cb.lessThanOrEqualTo(patient.get("dateNaissance"), maxDateNaissance));
            }
        }

        // Assurance active
        if (request.avecAssuranceActive() != null && request.avecAssuranceActive()) {
            predicates.add(cb.and(
                    cb.equal(assuranceJoin.get("estActive"), true),
                    cb.or(
                            cb.isNull(assuranceJoin.get("dateFin")),
                            cb.greaterThanOrEqualTo(assuranceJoin.get("dateFin"), LocalDate.now())
                    )
            ));
        }

        // Ordonnance en cours
        if (request.avecOrdonnanceEnCours() != null && request.avecOrdonnanceEnCours()) {
            Subquery<Long> ordonnanceSubquery = query.subquery(Long.class);
            Root<Ordonnance> ordonnanceRoot = ordonnanceSubquery.from(Ordonnance.class);
            ordonnanceSubquery.select(cb.count(ordonnanceRoot))
                    .where(cb.and(
                            cb.equal(ordonnanceRoot.get("patient"), patient),
                            ordonnanceRoot.get("statut").in(PrescriptionStatus.EN_ATTENTE, PrescriptionStatus.VALIDEE),
                            cb.isNull(ordonnanceRoot.get("dateSuppression"))
                    ));
            predicates.add(cb.greaterThan(ordonnanceSubquery, 0L));
        }

        // Créé par
        if (request.creePar() != null && !request.creePar().trim().isEmpty()) {
            predicates.add(cb.equal(patient.get("creePar"), request.creePar()));
        }

        // ============================================
        // CONSTRUCTION ET EXÉCUTION DES REQUÊTES
        // ============================================

        // Requête principale
        query.select(patient)
                .distinct(true)
                .where(predicates.toArray(new Predicate[0]));

        // Requête de count simplifiée (sans joins pour éviter les doublons)
        CriteriaQuery<Long> countQuery = cb.createQuery(Long.class);
        Root<Patient> countRoot = countQuery.from(Patient.class);

        List<Predicate> countPredicates = buildSimplePredicates(cb, countRoot, request);

        countQuery.select(cb.countDistinct(countRoot))
                .where(countPredicates.toArray(new Predicate[0]));

        // Exécution
        TypedQuery<Patient> typedQuery = entityManager.createQuery(query);
        typedQuery.setFirstResult((int) pageable.getOffset());
        typedQuery.setMaxResults(pageable.getPageSize());

        List<Patient> patients = typedQuery.getResultList();
        Long total = entityManager.createQuery(countQuery).getSingleResult();

        return new PageImpl<>(patients, pageable, total);
    }

    /**
     * Construit les prédicats simples pour la requête de count (sans joins)
     */
    private List<Predicate> buildSimplePredicates(CriteriaBuilder cb, Root<Patient> patient, PatientSearchRequest request) {
        List<Predicate> predicates = new ArrayList<>();

        // Patient non supprimé
        predicates.add(cb.isNull(patient.get("dateSuppression")));

        // NIR
        if (request.numeroSecuSociale() != null && !request.numeroSecuSociale().trim().isEmpty()) {
            String nirClean = request.getNumeroSecuSocialeClean();
            predicates.add(cb.like(patient.get("numeroSecu"), "%" + nirClean + "%"));
        }

        // Nom complet
        if (request.nomComplet() != null && !request.nomComplet().trim().isEmpty()) {
            String[] tokens = request.getNomCompletTokens();

            if (tokens.length > 0) {
                List<Predicate> nomPrenomPredicates = new ArrayList<>();

                for (String token : tokens) {
                    if (token.length() >= 2) {
                        Predicate nomMatch = cb.like(cb.lower(patient.get("nom")), "%" + token + "%");
                        Predicate prenomMatch = cb.like(cb.lower(patient.get("prenom")), "%" + token + "%");
                        nomPrenomPredicates.add(cb.or(nomMatch, prenomMatch));
                    }
                }

                if (!nomPrenomPredicates.isEmpty()) {
                    predicates.add(cb.and(nomPrenomPredicates.toArray(new Predicate[0])));
                }
            }
        }

        // Date de naissance
        if (request.dateNaissance() != null) {
            predicates.add(cb.equal(patient.get("dateNaissance"), request.dateNaissance()));
        }

        // Statuts
        if (request.statuts() != null && !request.statuts().isEmpty()) {
            predicates.add(patient.get("statut").in(request.statuts()));
        }

        // Créé par
        if (request.creePar() != null && !request.creePar().trim().isEmpty()) {
            predicates.add(cb.equal(patient.get("creePar"), request.creePar()));
        }

        return predicates;
    }

    @Override
    public Optional<Patient> findPatientByPhone(String phoneNumber) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<Patient> query = cb.createQuery(Patient.class);
        Root<Patient> patient = query.from(Patient.class);
        Join<Patient, PatientContact> contactJoin = patient.join("contacts");

        query.select(patient)
                .where(cb.and(
                        cb.equal(contactJoin.get("numeroTelephone"), phoneNumber),
                        cb.isNull(patient.get("dateSuppression"))
                ));

        List<Patient> results = entityManager.createQuery(query).getResultList();
        return results.isEmpty() ? Optional.empty() : Optional.of(results.getFirst());
    }

    @Override
    public long countPatientsWithActiveInsurance() {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<Long> query = cb.createQuery(Long.class);
        Root<Patient> patient = query.from(Patient.class);
        Join<Patient, PatientAssurance> assuranceJoin = patient.join("assurances");

        query.select(cb.countDistinct(patient))
                .where(cb.and(
                        cb.equal(assuranceJoin.get("estActive"), true),
                        cb.or(
                                cb.isNull(assuranceJoin.get("dateFin")),
                                cb.greaterThanOrEqualTo(assuranceJoin.get("dateFin"), LocalDate.now())
                        ),
                        cb.isNull(patient.get("dateSuppression"))
                ));

        return entityManager.createQuery(query).getSingleResult();
    }

    @Override
    public long countPatientsWithActivePrescription() {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<Long> query = cb.createQuery(Long.class);
        Root<Patient> patient = query.from(Patient.class);
        Join<Patient, Ordonnance> ordonnanceJoin = patient.join("ordonnances");

        query.select(cb.countDistinct(patient))
                .where(cb.and(
                        ordonnanceJoin.get("statut").in(PrescriptionStatus.EN_ATTENTE, PrescriptionStatus.VALIDEE),
                        cb.isNull(ordonnanceJoin.get("dateSuppression")),
                        cb.isNull(patient.get("dateSuppression"))
                ));

        return entityManager.createQuery(query).getSingleResult();
    }

    @Override
    public List<Patient> findPotentialDuplicates(String nom, String prenom, LocalDate dateNaissance) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<Patient> query = cb.createQuery(Patient.class);
        Root<Patient> patient = query.from(Patient.class);

        // Recherche de patients avec nom/prénom similaires et même date de naissance
        List<Predicate> predicates = new ArrayList<>();
        predicates.add(cb.isNull(patient.get("dateSuppression")));
        predicates.add(cb.equal(patient.get("dateNaissance"), dateNaissance));

        // Recherche floue sur nom et prénom
        Predicate nomSimilar = cb.or(
                cb.like(cb.lower(patient.get("nom")), "%" + nom.toLowerCase() + "%"),
                cb.like(cb.lower(patient.get("prenom")), "%" + nom.toLowerCase() + "%")
        );

        Predicate prenomSimilar = cb.or(
                cb.like(cb.lower(patient.get("prenom")), "%" + prenom.toLowerCase() + "%"),
                cb.like(cb.lower(patient.get("nom")), "%" + prenom.toLowerCase() + "%")
        );

        predicates.add(cb.and(nomSimilar, prenomSimilar));

        query.select(patient)
                .where(predicates.toArray(new Predicate[0]));

        return entityManager.createQuery(query).getResultList();
    }
}