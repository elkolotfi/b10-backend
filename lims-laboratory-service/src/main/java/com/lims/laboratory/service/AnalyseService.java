package com.lims.laboratory.service;

import com.lims.laboratory.dto.request.AnalyseRequestDTO;
import com.lims.laboratory.dto.request.AnalyseSearchDTO;
import com.lims.laboratory.dto.response.AnalyseResponseDTO;
import com.lims.laboratory.dto.response.PagedResponseDTO;
import com.lims.laboratory.entity.LaboratoireAnalyse;
import com.lims.laboratory.exception.AnalyseDuplicateException;
import com.lims.laboratory.exception.AnalyseNotFoundException;
import com.lims.laboratory.mapper.AnalyseMapper;
import com.lims.laboratory.repository.AnalyseRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class AnalyseService {

    private final AnalyseRepository analyseRepository;
    private final AnalyseMapper analyseMapper;

    // === OPÉRATIONS CRUD ===

    /**
     * Crée une nouvelle analyse
     */
    public AnalyseResponseDTO createAnalyse(AnalyseRequestDTO requestDTO) {
        log.info("Création d'une nouvelle analyse pour le laboratoire: {}", requestDTO.getLaboratoireId());

        // Vérifier l'unicité du code si fourni
        if (StringUtils.hasText(requestDTO.getCodeAnalyseLabo())) {
            if (analyseRepository.existsByLaboratoireIdAndCodeAnalyseLabo(
                    requestDTO.getLaboratoireId(),
                    requestDTO.getCodeAnalyseLabo())) {
                throw new AnalyseDuplicateException(
                        "Une analyse avec le code '" + requestDTO.getCodeAnalyseLabo() +
                                "' existe déjà pour ce laboratoire"
                );
            }
        }

        // Vérifier l'unicité de l'analyse référentiel
        if (analyseRepository.findByLaboratoireIdAndAnalyseReferentielId(
                requestDTO.getLaboratoireId(),
                requestDTO.getAnalyseReferentielId()).isPresent()) {
            throw new AnalyseDuplicateException(
                    "Cette analyse du référentiel est déjà configurée pour ce laboratoire"
            );
        }

        LaboratoireAnalyse entity = analyseMapper.toEntity(requestDTO);
        LaboratoireAnalyse savedEntity = analyseRepository.save(entity);

        log.info("Analyse créée avec succès - ID: {}", savedEntity.getId());
        return analyseMapper.toResponseDTO(savedEntity);
    }

    /**
     * Met à jour une analyse existante
     */
    public AnalyseResponseDTO updateAnalyse(UUID id, AnalyseRequestDTO requestDTO) {
        log.info("Mise à jour de l'analyse: {}", id);

        LaboratoireAnalyse existingEntity = analyseRepository.findById(id)
                .orElseThrow(() -> new AnalyseNotFoundException("Analyse non trouvée avec l'ID: " + id));

        // Vérifier l'unicité du code si modifié
        if (StringUtils.hasText(requestDTO.getCodeAnalyseLabo()) &&
                !requestDTO.getCodeAnalyseLabo().equals(existingEntity.getCodeAnalyseLabo())) {
            if (analyseRepository.existsByLaboratoireIdAndCodeAnalyseLabo(
                    existingEntity.getLaboratoireId(),
                    requestDTO.getCodeAnalyseLabo())) {
                throw new AnalyseDuplicateException(
                        "Une analyse avec le code '" + requestDTO.getCodeAnalyseLabo() +
                                "' existe déjà pour ce laboratoire"
                );
            }
        }

        analyseMapper.updateEntity(existingEntity, requestDTO);
        LaboratoireAnalyse savedEntity = analyseRepository.save(existingEntity);

        log.info("Analyse mise à jour avec succès - ID: {}", savedEntity.getId());
        return analyseMapper.toResponseDTO(savedEntity);
    }

    /**
     * Supprime une analyse
     */
    public void deleteAnalyse(UUID id) {
        log.info("Suppression de l'analyse: {}", id);

        if (!analyseRepository.existsById(id)) {
            throw new AnalyseNotFoundException("Analyse non trouvée avec l'ID: " + id);
        }

        analyseRepository.deleteById(id);
        log.info("Analyse supprimée avec succès - ID: {}", id);
    }

    // === CONSULTATIONS ===

    /**
     * Récupère une analyse par son ID
     */
    @Transactional(readOnly = true)
    public AnalyseResponseDTO findById(UUID id) {
        log.debug("Récupération de l'analyse: {}", id);

        LaboratoireAnalyse entity = analyseRepository.findById(id)
                .orElseThrow(() -> new AnalyseNotFoundException("Analyse non trouvée avec l'ID: " + id));

        return analyseMapper.toResponseDTO(entity);
    }

    /**
     * Recherche des analyses avec critères et pagination
     */
    @Transactional(readOnly = true)
    public PagedResponseDTO<AnalyseResponseDTO> searchAnalyses(
            AnalyseSearchDTO searchDTO,
            int page,
            int size,
            String sortBy,
            String sortDirection) {

        log.debug("Recherche d'analyses avec critères: {}", searchDTO);

        Sort sort = Sort.by(Sort.Direction.fromString(sortDirection), sortBy);
        Pageable pageable = PageRequest.of(page, size, sort);

        Page<LaboratoireAnalyse> analysesPage = analyseRepository.findAnalysesWithCriteria(
                searchDTO.getLaboratoireId(),
                searchDTO.getLaboratoireExamenId(),
                searchDTO.getNomAnalyse(),
                searchDTO.getCodeAnalyse(),
                searchDTO.getAnalyseActive(),
                searchDTO.getSousTraite(),
                searchDTO.getTechnique(),
                searchDTO.getAutomate(),
                pageable
        );

        List<AnalyseResponseDTO> analysesDTO = analyseMapper.toResponseDTOList(analysesPage.getContent());

        return PagedResponseDTO.<AnalyseResponseDTO>builder()
                .content(analysesDTO)
                .page(analysesPage.getNumber())
                .size(analysesPage.getSize())
                .totalElements(analysesPage.getTotalElements())
                .totalPages(analysesPage.getTotalPages())
                .first(analysesPage.isFirst())
                .last(analysesPage.isLast())
                .build();
    }

    /**
     * Récupère toutes les analyses actives d'un laboratoire
     */
    @Transactional(readOnly = true)
    public List<AnalyseResponseDTO> findActiveAnalysesByLaboratoire(UUID laboratoireId) {
        log.debug("Récupération des analyses actives du laboratoire: {}", laboratoireId);

        List<LaboratoireAnalyse> analyses = analyseRepository.findByLaboratoireIdAndAnalyseActiveTrue(laboratoireId);
        return analyseMapper.toResponseDTOList(analyses);
    }

    /**
     * Récupère toutes les analyses d'un examen
     */
    @Transactional(readOnly = true)
    public List<AnalyseResponseDTO> findAnalysesByExamen(UUID laboratoireExamenId) {
        log.debug("Récupération des analyses de l'examen: {}", laboratoireExamenId);

        List<LaboratoireAnalyse> analyses = analyseRepository.findByLaboratoireExamenIdAndAnalyseActiveTrue(laboratoireExamenId);
        return analyseMapper.toResponseDTOList(analyses);
    }

    /**
     * Active/désactive une analyse
     */
    public AnalyseResponseDTO toggleActivation(UUID id, boolean active) {
        log.info("Modification du statut de l'analyse {} - Actif: {}", id, active);

        LaboratoireAnalyse entity = analyseRepository.findById(id)
                .orElseThrow(() -> new AnalyseNotFoundException("Analyse non trouvée avec l'ID: " + id));

        entity.setAnalyseActive(active);
        LaboratoireAnalyse savedEntity = analyseRepository.save(entity);

        log.info("Statut de l'analyse modifié avec succès - ID: {}, Actif: {}", savedEntity.getId(), active);
        return analyseMapper.toResponseDTO(savedEntity);
    }

    // === STATISTIQUES ===

    /**
     * Statistiques des analyses d'un laboratoire
     */
    @Transactional(readOnly = true)
    public Map<String, Object> getStatistiquesAnalyses(UUID laboratoireId) {
        log.debug("Génération des statistiques d'analyses pour le laboratoire: {}", laboratoireId);

        long totalAnalyses = analyseRepository.countActiveAnalysesByLaboratoire(laboratoireId);
        long analysesSousTraitees = analyseRepository.countSousTraiteesByLaboratoire(laboratoireId);

        List<Object[]> statsRepartition = analyseRepository.getStatistiquesSousTraitance(laboratoireId);

        return Map.of(
                "totalAnalyses", totalAnalyses,
                "analysesSousTraitees", analysesSousTraitees,
                "analysesInternes", totalAnalyses - analysesSousTraitees,
                "pourcentageSousTraitance", totalAnalyses > 0 ? (analysesSousTraitees * 100.0 / totalAnalyses) : 0.0,
                "repartitionSousTraitance", statsRepartition
        );
    }
}