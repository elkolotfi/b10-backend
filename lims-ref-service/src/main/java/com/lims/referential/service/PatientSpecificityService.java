package com.lims.referential.service;

import com.lims.referential.entity.PatientSpecificity;
import com.lims.referential.entity.SpecificityCategory;
import com.lims.referential.repository.PatientSpecificityRepository;
import com.lims.referential.repository.SpecificityCategoryRepository;
import com.lims.referential.dto.request.PatientSpecificityRequestDTO;
import com.lims.referential.dto.response.PatientSpecificityResponseDTO;
import com.lims.referential.dto.common.PagedResponseDTO;
import com.lims.referential.exception.ResourceNotFoundException;
import com.lims.referential.mapper.PatientSpecificityMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class PatientSpecificityService {

    private final PatientSpecificityRepository patientSpecificityRepository;
    private final SpecificityCategoryRepository specificityCategoryRepository;
    private final PatientSpecificityMapper patientSpecificityMapper;

    @Cacheable(value = "patient-specificities", key = "'all-' + #pageable.pageNumber + '-' + #pageable.pageSize")
    public PagedResponseDTO<PatientSpecificityResponseDTO> findAll(Pageable pageable) {
        log.debug("Récupération de toutes les spécificités patient - page: {}, size: {}", pageable.getPageNumber(), pageable.getPageSize());

        Page<PatientSpecificity> specificityPage = patientSpecificityRepository.findAll(pageable);
        List<PatientSpecificityResponseDTO> specificitiesDTOs = specificityPage.getContent()
                .stream()
                .map(patientSpecificityMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<PatientSpecificityResponseDTO>builder()
                .content(specificitiesDTOs)
                .page(specificityPage.getNumber())
                .size(specificityPage.getSize())
                .totalElements(specificityPage.getTotalElements())
                .totalPages(specificityPage.getTotalPages())
                .first(specificityPage.isFirst())
                .last(specificityPage.isLast())
                .empty(specificityPage.isEmpty())
                .build();
    }

    @Cacheable(value = "patient-specificities", key = "#id")
    public PatientSpecificityResponseDTO findById(UUID id) {
        log.debug("Recherche de la spécificité patient avec l'ID: {}", id);

        PatientSpecificity specificity = patientSpecificityRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Spécificité patient non trouvée avec l'ID: " + id));

        return patientSpecificityMapper.toResponseDTO(specificity);
    }

    public PagedResponseDTO<PatientSpecificityResponseDTO> findWithFilters(
            String categorie, String niveauAlerte, Boolean actif, Pageable pageable) {

        log.debug("Filtrage des spécificités - catégorie: {}, niveau: {}, actif: {}",
                categorie, niveauAlerte, actif);

        Page<PatientSpecificity> specificityPage = patientSpecificityRepository.findWithFilters(
                categorie, niveauAlerte, actif, pageable);
        List<PatientSpecificityResponseDTO> specificitiesDTOs = specificityPage.getContent()
                .stream()
                .map(patientSpecificityMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<PatientSpecificityResponseDTO>builder()
                .content(specificitiesDTOs)
                .page(specificityPage.getNumber())
                .size(specificityPage.getSize())
                .totalElements(specificityPage.getTotalElements())
                .totalPages(specificityPage.getTotalPages())
                .first(specificityPage.isFirst())
                .last(specificityPage.isLast())
                .empty(specificityPage.isEmpty())
                .build();
    }

    @Cacheable(value = "patient-specificities", key = "'instructions-' + #specificityId + '-' + #analyseCodes.hashCode()")
    public Map<String, Object> getInstructionsPreAnalytiques(UUID specificityId, List<String> analyseCodes) {
        log.debug("Récupération des instructions pré-analytiques pour la spécificité: {} et les analyses: {}",
                specificityId, analyseCodes);

        PatientSpecificity specificity = patientSpecificityRepository.findById(specificityId)
                .orElseThrow(() -> new ResourceNotFoundException("Spécificité patient non trouvée avec l'ID: " + specificityId));

        List<String> analysesContreIndiquees = specificity.getAnalysesContreIndiquees();
        List<String> analysesModifiees = specificity.getAnalysesModifiees();

        List<String> conflits = analyseCodes.stream()
                .filter(analysesContreIndiquees::contains)
                .toList();

        List<String> modifications = analyseCodes.stream()
                .filter(analysesModifiees::contains)
                .toList();

        return Map.of(
                "specificite", specificity.getTitre(),
                "niveauAlerte", specificity.getNiveauAlerte(),
                "instructionsPreleveur", specificity.getInstructionsPreleveur(),
                "instructionsTechnique", specificity.getInstructionsTechnique(),
                "analysesContreIndiquees", conflits,
                "analysesModifiees", modifications,
                "tempsSupplementaire", specificity.getTempsSupplementaireMinutes()
        );
    }

    @Cacheable(value = "patient-specificities", key = "'categories'")
    public List<Map<String, Object>> getCategoriesDynamiques() {
        log.debug("Récupération des catégories dynamiques");

        List<SpecificityCategory> categories = specificityCategoryRepository.findAllByActifTrueOrderByOrdreAffichage();

        return categories.stream()
                .map(cat -> {
                    // ✅ SOLUTION PROPRE: Utiliser Map.of avec des types compatibles ou HashMap
                    Map<String, Object> categoryMap = new java.util.HashMap<>();
                    categoryMap.put("id", cat.getId());
                    categoryMap.put("nom", cat.getNom());
                    categoryMap.put("description", cat.getDescription());
                    categoryMap.put("couleur", cat.getCouleur());
                    categoryMap.put("icone", cat.getIcone());
                    return categoryMap;
                })
                .toList();
    }

    @Transactional
    @CacheEvict(value = "patient-specificities", allEntries = true)
    public PatientSpecificityResponseDTO create(PatientSpecificityRequestDTO requestDTO) {
        log.info("Création d'une nouvelle spécificité patient: {}", requestDTO.getTitre());

        PatientSpecificity specificity = patientSpecificityMapper.toEntity(requestDTO);
        PatientSpecificity savedSpecificity = patientSpecificityRepository.save(specificity);

        log.info("Spécificité patient créée avec succès - ID: {}", savedSpecificity.getId());
        return patientSpecificityMapper.toResponseDTO(savedSpecificity);
    }

    @Transactional
    @CacheEvict(value = "patient-specificities", allEntries = true)
    public PatientSpecificityResponseDTO update(UUID id, PatientSpecificityRequestDTO requestDTO) {
        log.info("Mise à jour de la spécificité patient avec l'ID: {}", id);

        PatientSpecificity existingSpecificity = patientSpecificityRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Spécificité patient non trouvée avec l'ID: " + id));

        patientSpecificityMapper.updateEntityFromDTO(requestDTO, existingSpecificity);
        PatientSpecificity updatedSpecificity = patientSpecificityRepository.save(existingSpecificity);

        log.info("Spécificité patient mise à jour avec succès - ID: {}", updatedSpecificity.getId());
        return patientSpecificityMapper.toResponseDTO(updatedSpecificity);
    }

    @Transactional
    @CacheEvict(value = "patient-specificities", allEntries = true)
    public void delete(UUID id) {
        log.info("Suppression de la spécificité patient avec l'ID: {}", id);

        PatientSpecificity specificity = patientSpecificityRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Spécificité patient non trouvée avec l'ID: " + id));

        specificity.markAsDeleted();
        patientSpecificityRepository.save(specificity);

        log.info("Spécificité patient supprimée avec succès - ID: {}", id);
    }

    @Cacheable(value = "patient-specificities", key = "'stats'")
    public Map<String, Object> getStatistics() {
        log.debug("Récupération des statistiques des spécificités patient");

        long totalSpecificites = patientSpecificityRepository.count();
        List<Object[]> specificitesByNiveau = patientSpecificityRepository.getSpecificitiesByNiveauAlerte();

        Map<String, Long> niveauxCount = specificitesByNiveau.stream()
                .collect(java.util.stream.Collectors.toMap(
                        obj -> obj[0].toString(),
                        obj -> (Long) obj[1]
                ));

        return Map.of(
                "totalSpecificites", totalSpecificites,
                "specificitesByNiveau", niveauxCount
        );
    }
}