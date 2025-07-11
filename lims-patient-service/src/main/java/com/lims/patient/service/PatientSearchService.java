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
import org.springframework.util.StringUtils;

import java.time.LocalDate;
import java.time.Period;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Service de recherche de patients - Version adaptée avec nomComplet et Specifications dynamiques
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class PatientSearchService {

    private final PatientRepository patientRepository;

    /**
     * Recherche de patients avec critères multiples - VERSION ADAPTÉE
     * Support du nomComplet ET des critères séparés
     */
    public PatientSearchResponse searchPatients(PatientSearchRequest request) {
        log.info("Recherche de patients avec critères: {}", request);

        // Validation des critères - si tout est vide, retourner une page vide
        if (isEmptySearchRequest(request)) {
            log.warn("Recherche sans critères - retour d'une page vide");
            return PatientSearchResponse.builder()
                    .patients(List.of())
                    .currentPage(request.page())
                    .totalPages(0)
                    .totalElements(0L)
                    .pageSize(request.size())
                    .build();
        }

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

        // Construction de la specification selon le mode de recherche
        Specification<Patient> specification = buildSearchSpecification(request);

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
     * Construction de la specification selon le mode de recherche
     */
    private Specification<Patient> buildSearchSpecification(PatientSearchRequest request) {
        Specification<Patient> spec = Specification.where(PatientSpecifications.notDeleted());

        // Mode recherche par nom complet (prioritaire)
        if (request.isNomCompletSearch()) {
            log.debug("Mode recherche par nom complet: {}", request.nomComplet());
            spec = spec.and(PatientSpecifications.nomCompletAdvanced(request.nomComplet()));
        }
        // Mode recherche par nom/prénom séparés
        else if (request.isNomPrenomSearch()) {
            log.debug("Mode recherche par nom/prénom séparés: {} / {}", request.nom(), request.prenom());
            if (StringUtils.hasText(request.nom())) {
                spec = spec.and(PatientSpecifications.hasNom(request.nom()));
            }
            if (StringUtils.hasText(request.prenom())) {
                spec = spec.and(PatientSpecifications.hasPrenom(request.prenom()));
            }
        }

        // Ajout des autres critères
        spec = addOtherCriteria(spec, request);

        return spec;
    }

    /**
     * Ajoute les autres critères de recherche à la specification
     */
    private Specification<Patient> addOtherCriteria(Specification<Patient> spec, PatientSearchRequest request) {
        if (StringUtils.hasText(request.numeroSecu())) {
            spec = spec.and(PatientSpecifications.hasNumeroSecu(request.numeroSecu()));
        }

        if (StringUtils.hasText(request.email())) {
            boolean emailExactMatch = isEmailExactSearch(request);
            spec = spec.and(emailExactMatch
                    ? PatientSpecifications.hasEmail(request.email())
                    : PatientSpecifications.hasEmailContaining(request.email()));
        }

        if (StringUtils.hasText(request.telephone())) {
            spec = spec.and(PatientSpecifications.hasTelephone(request.telephone()));
        }

        if (StringUtils.hasText(request.ville())) {
            spec = spec.and(PatientSpecifications.hasVille(request.ville()));
        }

        if (StringUtils.hasText(request.codePostal())) {
            spec = spec.and(PatientSpecifications.hasCodePostal(request.codePostal()));
        }

        if (request.dateNaissance() != null) {
            spec = spec.and(PatientSpecifications.hasDateNaissance(request.dateNaissance()));
        }

        if (request.sexe() != null) {
            spec = spec.and(PatientSpecifications.hasSexe(request.sexe()));
        }

        if (request.statut() != null) {
            spec = spec.and(PatientSpecifications.hasStatut(request.statut()));
        }

        return spec;
    }

    /**
     * Recherche rapide par nom complet avec limite de résultats
     */
    public List<PatientSummaryResponse> quickSearchByNomComplet(String nomComplet) {
        log.info("Recherche rapide par nom complet: {}", nomComplet);

        if (!StringUtils.hasText(nomComplet)) {
            return List.of();
        }

        Specification<Patient> spec = Specification.where(PatientSpecifications.notDeleted())
                .and(PatientSpecifications.nomCompletAdvanced(nomComplet));

        // Limiter à 10 résultats pour la recherche rapide
        Pageable pageable = PageRequest.of(0, 10, Sort.by(Sort.Direction.ASC, "nom", "prenom"));

        List<Patient> patients = patientRepository.findAll(spec, pageable).getContent();

        return patients.stream()
                .map(this::mapToSummaryResponse)
                .collect(Collectors.toList());
    }

    /**
     * Recherche par nom complet avec pagination
     */
    public PatientSearchResponse searchByNomComplet(String nomComplet, int page, int size) {
        log.info("Recherche par nom complet avec pagination: {} (page: {}, size: {})", nomComplet, page, size);

        PatientSearchRequest request = PatientSearchRequest.builder()
                .nomComplet(nomComplet)
                .page(page)
                .size(size)
                .sortBy("nom")
                .sortDirection("asc")
                .build();

        return searchPatients(request);
    }

    /**
     * Suggestions d'autocomplétion pour le nom complet
     */
    public List<String> suggestNomComplet(String input) {
        if (!StringUtils.hasText(input) || input.length() < 2) {
            return List.of();
        }

        Specification<Patient> spec = Specification.where(PatientSpecifications.notDeleted())
                .and(PatientSpecifications.nomCompletContains(input));

        Pageable pageable = PageRequest.of(0, 5);

        List<Patient> patients = patientRepository.findAll(spec, pageable).getContent();

        return patients.stream()
                .map(patient -> String.format("%s %s", patient.getNom(), patient.getPrenom()).trim())
                .distinct()
                .collect(Collectors.toList());
    }

    /**
     * Recherche de patients par nom et prénom (rétrocompatibilité)
     */
    public List<PatientSummaryResponse> searchByNomPrenom(String nom, String prenom) {
        log.info("Recherche par nom: {} et prénom: {}", nom, prenom);

        PatientSearchRequest request = PatientSearchRequest.builder()
                .nom(nom)
                .prenom(prenom)
                .page(0)
                .size(50)
                .sortBy("nom")
                .sortDirection("asc")
                .build();

        return searchPatients(request).patients();
    }

    /**
     * Recherche rapide (typeahead) - version adaptée
     */
    public List<PatientSummaryResponse> quickSearch(String query, int limit) {
        log.info("Recherche rapide: {}", query);

        if (query == null || query.trim().length() < 2) {
            return List.of();
        }

        // Recherche dans nom complet, nom, prénom ou email
        Specification<Patient> spec = Specification.where(PatientSpecifications.notDeleted())
                .and(PatientSpecifications.nomCompletContains(query)
                        .or(PatientSpecifications.hasNom(query))
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
     * Vérifie si la requête de recherche est complètement vide
     */
    private boolean isEmptySearchRequest(PatientSearchRequest request) {
        return !request.isNomCompletSearch() &&
                !request.isNomPrenomSearch() &&
                !StringUtils.hasText(request.numeroSecu()) &&
                !StringUtils.hasText(request.email()) &&
                !StringUtils.hasText(request.telephone()) &&
                !StringUtils.hasText(request.ville()) &&
                !StringUtils.hasText(request.codePostal()) &&
                request.dateNaissance() == null &&
                request.sexe() == null &&
                request.statut() == null;
    }

    /**
     * Détermine si c'est une recherche exacte par email
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
        return isOnlyEmailSearch(request);
    }

    /**
     * Vérifie si seul l'email est utilisé comme critère
     */
    private boolean isOnlyEmailSearch(PatientSearchRequest request) {
        return !request.isNomCompletSearch() &&
                !request.isNomPrenomSearch() &&
                (request.numeroSecu() == null || request.numeroSecu().trim().isEmpty()) &&
                (request.telephone() == null || request.telephone().trim().isEmpty()) &&
                (request.ville() == null || request.ville().trim().isEmpty()) &&
                request.codePostal() == null &&
                request.dateNaissance() == null &&
                request.sexe() == null &&
                request.statut() == null;
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
        String nomComplet = String.format("%s %s",
                patient.getNom() != null ? patient.getNom() : "",
                patient.getPrenom() != null ? patient.getPrenom() : "").trim();

        Integer age = null;
        if (patient.getDateNaissance() != null) {
            age = Period.between(patient.getDateNaissance(), LocalDate.now()).getYears();
        }

        return PatientSummaryResponse.builder()
                .id(patient.getId().toString())
                .nomComplet(nomComplet)
                .email(patient.getEmail())
                .telephone(patient.getTelephone())
                .dateNaissance(patient.getDateNaissance())
                .age(age)
                .sexe(patient.getSexe())
                .ville(patient.getVille())
                .statut(patient.getStatut())
                .dateCreation(patient.getDateCreation())
                .build();
    }

    // ===== MÉTHODES STATISTIQUES (inchangées) =====

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