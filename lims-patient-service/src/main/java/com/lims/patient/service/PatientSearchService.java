package com.lims.patient.service;

import com.lims.patient.dto.request.PatientSearchRequest;
import com.lims.patient.dto.response.PatientSearchResponse;
import com.lims.patient.dto.response.PatientSummaryResponse;
import com.lims.patient.entity.Patient;
import com.lims.patient.repository.PatientRepository;
import com.lims.patient.specification.PatientSpecifications;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Service de recherche de patients - Version avec Specifications dynamiques
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class PatientSearchService {

    private final PatientRepository patientRepository;

    /**
     * Recherche de patients avec critères multiples - VERSION DYNAMIQUE
     * Construction dynamique de la requête selon les critères fournis
     */
    public PatientSearchResponse searchPatients(PatientSearchRequest request) {
        log.info("Recherche de patients avec critères: {}", request);

        // Validation et correction des paramètres de pagination
        int page = Math.max(0, request.page());
        int size = request.size();
        if (size <= 0) {
            size = 20; // Valeur par défaut
            log.debug("Taille de page corrigée de {} à {}", request.size(), size);
        }
        size = Math.min(100, size); // Limite maximale

        // Construction du tri
        Sort sort = buildSort(request.sortBy(), request.sortDirection());
        Pageable pageable = PageRequest.of(page, size, sort);

        // Déterminer si c'est une recherche exacte par email
        boolean emailExactMatch = isEmailExactSearch(request);

        log.debug("Recherche email exacte: {}", emailExactMatch);

        // Construction de la specification dynamique
        Specification<Patient> specification = PatientSpecifications.searchCriteria(
                request.nom(),
                request.prenom(),
                request.numeroSecu(),
                request.email(),
                request.telephone(),
                request.ville(),
                request.codePostal(),
                request.dateNaissance(),
                request.sexe(),
                request.statut(),
                emailExactMatch
        );

        // Exécution de la requête
        Page<Patient> patientsPage = patientRepository.findAll(specification, pageable);

        log.info("Trouvé {} patients sur {} total",
                patientsPage.getNumberOfElements(),
                patientsPage.getTotalElements());

        // Mapping vers les DTOs de réponse
        List<PatientSummaryResponse> patients = patientsPage.stream()
                .map(this::mapToSummaryResponse)
                .collect(Collectors.toList());

        return PatientSearchResponse.builder()
                .patients(patients)
                .currentPage(patientsPage.getNumber())
                .totalPages(patientsPage.getTotalPages())
                .totalElements(patientsPage.getTotalElements())
                .pageSize(patientsPage.getSize())
                .build();
    }

    /**
     * Détermine si c'est une recherche exacte par email
     * (email seul ou email qui ressemble à une adresse complète)
     */
    private boolean isEmailExactSearch(PatientSearchRequest request) {
        if (request.email() == null || request.email().trim().isEmpty()) {
            return false;
        }

        String email = request.email().trim();

        // Si l'email contient @ et semble être une adresse complète, recherche exacte
        if (email.contains("@") && email.contains(".")) {
            return true;
        }

        // Si c'est le seul critère de recherche, recherche exacte aussi
        return areOtherCriteriaEmpty(request);
    }

    /**
     * Vérifie si les autres critères sont vides
     */
    private boolean areOtherCriteriaEmpty(PatientSearchRequest request) {
        return (request.nom() == null || request.nom().trim().isEmpty()) &&
                (request.prenom() == null || request.prenom().trim().isEmpty()) &&
                (request.numeroSecu() == null || request.numeroSecu().trim().isEmpty()) &&
                (request.telephone() == null || request.telephone().trim().isEmpty()) &&
                (request.ville() == null || request.ville().trim().isEmpty()) &&
                request.codePostal() == null &&
                request.dateNaissance() == null &&
                request.sexe() == null &&
                request.statut() == null;
    }

    /**
     * Recherche de patients par nom et prénom
     */
    public List<PatientSummaryResponse> searchByNomPrenom(String nom, String prenom) {
        log.info("Recherche par nom: {} et prénom: {}", nom, prenom);

        Specification<Patient> spec = PatientSpecifications.searchCriteria(
                nom, prenom, null, null, null, null, null, null, null, null, false);

        List<Patient> patients = patientRepository.findAll(spec);

        return patients.stream()
                .map(this::mapToSummaryResponse)
                .collect(Collectors.toList());
    }

    /**
     * Recherche rapide (typeahead)
     */
    public List<PatientSummaryResponse> quickSearch(String query, int limit) {
        log.info("Recherche rapide: {}", query);

        if (query == null || query.trim().length() < 2) {
            return List.of();
        }

        // Recherche dans nom, prénom ou email
        Specification<Patient> spec = Specification.where(PatientSpecifications.notDeleted())
                .and(PatientSpecifications.hasNom(query)
                        .or(PatientSpecifications.hasPrenom(query))
                        .or(PatientSpecifications.hasEmailContaining(query)));

        // Pagination pour limiter les résultats
        Pageable pageable = PageRequest.of(0, limit, Sort.by("dateCreation").descending());
        Page<Patient> patients = patientRepository.findAll(spec, pageable);

        return patients.stream()
                .map(this::mapToSummaryResponse)
                .collect(Collectors.toList());
    }

    /**
     * Construit l'objet Sort pour la pagination
     */
    private Sort buildSort(String sortBy, String sortDirection) {
        String[] allowedSortFields = {
                "nom", "prenom", "dateNaissance", "ville", "email",
                "telephone", "dateCreation", "dateModification", "statut"
        };

        String validSortBy = "dateCreation"; // Par défaut
        if (sortBy != null && List.of(allowedSortFields).contains(sortBy)) {
            validSortBy = sortBy;
        }

        Sort.Direction direction = Sort.Direction.DESC; // Par défaut
        if ("ASC".equalsIgnoreCase(sortDirection)) {
            direction = Sort.Direction.ASC;
        }

        return Sort.by(direction, validSortBy);
    }

    /**
     * Mappe un Patient vers PatientSummaryResponse
     */
    private PatientSummaryResponse mapToSummaryResponse(Patient patient) {
        return PatientSummaryResponse.builder()
                .id(patient.getId().toString())
                .nomComplet(patient.getNomComplet())
                .email(patient.getEmail())
                .telephone(patient.getTelephone())
                .dateNaissance(patient.getDateNaissance())
                .age(patient.getAge())
                .sexe(patient.getSexe())
                .ville(patient.getVille())
                .statut(patient.getStatut())
                .dateCreation(patient.getDateCreation())
                .build();
    }

    // ===== AUTRES MÉTHODES (inchangées) =====

    public long countActivePatients() {
        return patientRepository.countActivePatients();
    }

    public List<Object[]> getPatientStatisticsByStatus() {
        return patientRepository.countPatientsByStatus();
    }

    public List<Object[]> getPatientStatisticsByGender() {
        return patientRepository.countPatientsByGender();
    }

    public List<Object[]> getPatientStatisticsByCity() {
        return patientRepository.countPatientsByCity();
    }
}