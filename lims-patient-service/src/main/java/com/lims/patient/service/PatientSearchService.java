package com.lims.patient.service;

import com.lims.patient.dto.PageInfo;
import com.lims.patient.dto.SearchStats;
import com.lims.patient.dto.request.PatientSearchRequest;
import com.lims.patient.dto.response.*;
import com.lims.patient.entity.Patient;
import com.lims.patient.enums.PatientStatus;
import com.lims.patient.mapper.PatientMapper;
import com.lims.patient.repository.PatientRepository;
import com.lims.patient.repository.PatientSearchRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.YearMonth;
import java.util.List;

/**
 * Service pour la recherche et les statistiques des patients
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class PatientSearchService {

    private final PatientRepository patientRepository;
    private final PatientSearchRepository patientSearchRepository;
    private final PatientMapper patientMapper;

    /**
     * Recherche de patients avec critères multiples et pagination
     */
    public PatientSearchResponse searchPatients(PatientSearchRequest request) {
        log.info("Recherche de patients avec critères: {}", request);

        // 1. Construction du Pageable avec tri
        Sort sort = buildSort(request.sort());
        Pageable pageable = PageRequest.of(request.page(), request.size(), sort);

        // 2. Exécution de la recherche
        Page<Patient> patientsPage = patientSearchRepository.searchPatients(request, pageable);

        // 3. Conversion en DTOs
        List<PatientSummaryResponse> patientSummaries = patientsPage.getContent()
                .stream()
                .map(patientMapper::toPatientSummaryResponse)
                .toList();

        // 4. Informations de pagination
        PageInfo pageInfo = PageInfo.builder()
                .currentPage(patientsPage.getNumber())
                .totalPages(patientsPage.getTotalPages())
                .pageSize(patientsPage.getSize())
                .totalElements(patientsPage.getTotalElements())
                .hasNext(patientsPage.hasNext())
                .hasPrevious(patientsPage.hasPrevious())
                .build();

        // 5. Statistiques de recherche
        SearchStats stats = calculateSearchStats(request);

        return PatientSearchResponse.builder()
                .patients(patientSummaries)
                .pageInfo(pageInfo)
                .stats(stats)
                .build();
    }

    /**
     * Recherche un patient par son NIR
     */
    public PatientSummaryResponse findPatientByNir(String nir) {
        log.info("Recherche patient par NIR");

        return patientRepository.findByNumeroSecuAndDateSuppressionIsNull(nir)
                .map(patientMapper::toPatientSummaryResponse)
                .orElse(null);
    }

    /**
     * Recherche un patient par son téléphone
     */
    public PatientSummaryResponse findPatientByPhone(String phone) {
        log.info("Recherche patient par téléphone");

        return patientSearchRepository.findPatientByPhone(phone)
                .map(patientMapper::toPatientSummaryResponse)
                .orElse(null);
    }

    /**
     * Calcule les statistiques générales des patients
     */
    public SearchStats getPatientStatistics() {
        log.info("Calcul des statistiques patients");

        LocalDate debutMoisCourant = YearMonth.now().atDay(1);

        return SearchStats.builder()
                .totalPatients(patientRepository.countByDateSuppressionIsNull())
                .patientsActifs(patientRepository.countByStatutAndDateSuppressionIsNull(PatientStatus.ACTIF))
                .patientsAvecAssurance(patientSearchRepository.countPatientsWithActiveInsurance())
                .patientsAvecOrdonnance(patientSearchRepository.countPatientsWithActivePrescription())
                .nouveauxPatientsMoisCourant(
                        patientRepository.countByDateCreationGreaterThanEqualAndDateSuppressionIsNull(
                                debutMoisCourant.atStartOfDay()))
                .build();
    }

    /**
     * Construit l'objet Sort à partir de la chaîne de tri
     */
    private Sort buildSort(String sortString) {
        if (sortString == null || sortString.trim().isEmpty()) {
            return Sort.by(Sort.Direction.ASC, "nom");
        }

        String[] parts = sortString.split(",");
        String property = parts[0];
        Sort.Direction direction = parts.length > 1 && "desc".equalsIgnoreCase(parts[1])
                ? Sort.Direction.DESC
                : Sort.Direction.ASC;

        return Sort.by(direction, property);
    }

    /**
     * Calcule les statistiques spécifiques à la recherche
     */
    private SearchStats calculateSearchStats(PatientSearchRequest request) {
        // Statistiques simplifiées pour la recherche
        return SearchStats.builder()
                .totalPatients(patientRepository.countByDateSuppressionIsNull())
                .patientsActifs(patientRepository.countByStatutAndDateSuppressionIsNull(PatientStatus.ACTIF))
                .patientsAvecAssurance(0L) // À calculer si nécessaire
                .patientsAvecOrdonnance(0L) // À calculer si nécessaire
                .nouveauxPatientsMoisCourant(0L) // À calculer si nécessaire
                .build();
    }
}
