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

import java.util.*;
import java.util.stream.Collectors;

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

    // Méthodes à ajouter dans PatientSpecificityService.java

    /**
     * Récupère les spécificités groupées par catégorie
     * Utilisé par le composant PatientSituation
     */
    @Cacheable(value = "patient-specificities", key = "'grouped-by-category'")
    public Map<String, Object> getSpecificitiesGroupedByCategory() {
        log.debug("Récupération des spécificités groupées par catégorie");

        // Récupérer toutes les catégories actives
        List<SpecificityCategory> categories = specificityCategoryRepository.findAllByActifTrueOrderByOrdreAffichage();

        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> categoriesData = new ArrayList<>();

        for (SpecificityCategory category : categories) {
            // Récupérer les spécificités de cette catégorie
            List<PatientSpecificity> specificities = patientSpecificityRepository
                    .findByCategoryIdAndActifTrueOrderByPrioritePreleveurDesc(category.getId());

            Map<String, Object> categoryData = new HashMap<>();
            categoryData.put("id", category.getId());
            categoryData.put("nom", category.getNom());
            categoryData.put("description", category.getDescription());
            categoryData.put("couleur", category.getCouleur());
            categoryData.put("icone", category.getIcone());
            categoryData.put("ordreAffichage", category.getOrdreAffichage());

            // Convertir les spécificités en DTOs
            List<PatientSpecificityResponseDTO> specificitiesDTO = specificities.stream()
                    .map(patientSpecificityMapper::toResponseDTO)
                    .toList();

            categoryData.put("specificities", specificitiesDTO);
            categoryData.put("count", specificitiesDTO.size());

            categoriesData.add(categoryData);
        }

        result.put("categories", categoriesData);
        result.put("totalCategories", categoriesData.size());
        result.put("totalSpecificities", categoriesData.stream()
                .mapToInt(cat -> (Integer) cat.get("count"))
                .sum());

        return result;
    }

    /**
     * Récupère toutes les catégories actives (méthode de base)
     */
    @Cacheable(value = "patient-specificities", key = "'categories'")
    public List<Map<String, Object>> getCategories() {
        log.debug("Récupération de toutes les catégories actives");

        List<SpecificityCategory> categories = specificityCategoryRepository.findAllByActifTrueOrderByOrdreAffichage();

        return categories.stream()
                .map(cat -> {
                    Map<String, Object> categoryMap = new HashMap<>();
                    categoryMap.put("id", cat.getId());
                    categoryMap.put("nom", cat.getNom());
                    categoryMap.put("description", cat.getDescription());
                    categoryMap.put("couleur", cat.getCouleur());
                    categoryMap.put("icone", cat.getIcone());
                    categoryMap.put("ordreAffichage", cat.getOrdreAffichage());
                    categoryMap.put("actif", cat.getActif());
                    return categoryMap;
                })
                .toList();
    }

    /**
     * Récupère les catégories avec leurs spécificités associées
     */
    @Cacheable(value = "patient-specificities", key = "'categories-with-specificities'")
    public List<Map<String, Object>> getCategoriesWithSpecificities() {
        log.debug("Récupération des catégories avec spécificités");

        return getCategories().stream()
                .map(category -> {
                    Map<String, Object> categoryMap = new HashMap<>();
                    categoryMap.put("id", category.get("id"));
                    categoryMap.put("nom", category.get("nom"));
                    categoryMap.put("description", category.get("description"));
                    categoryMap.put("couleur", category.get("couleur"));
                    categoryMap.put("icone", category.get("icone"));
                    categoryMap.put("ordreAffichage", category.get("ordreAffichage"));

                    // Récupérer les spécificités de cette catégorie
                    String categoryId = (String) category.get("id");
                    List<PatientSpecificity> specificities = patientSpecificityRepository
                            .findByCategoryIdAndActifTrueOrderByPrioritePreleveurDesc(categoryId);

                    List<PatientSpecificityResponseDTO> specificitiesDTO = specificities.stream()
                            .map(patientSpecificityMapper::toResponseDTO)
                            .toList();

                    categoryMap.put("specificities", specificitiesDTO);
                    return categoryMap;
                })
                .toList();
    }

    /**
     * Récupère les spécificités par catégorie avec pagination
     */
    public PagedResponseDTO<PatientSpecificityResponseDTO> findByCategory(String categoryId, Pageable pageable) {
        log.debug("Recherche des spécificités pour la catégorie: {}", categoryId);

        Page<PatientSpecificity> specificityPage = patientSpecificityRepository
                .findByCategoryIdAndActifTrue(categoryId, pageable);

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

    /**
     * Récupère les statistiques sur les spécificités
     */
    @Cacheable(value = "patient-specificities", key = "'statistics'")
    public Map<String, Object> getStatistics() {
        log.debug("Génération des statistiques des spécificités");

        Map<String, Object> stats = new HashMap<>();

        // Statistiques générales
        long totalSpecificities = patientSpecificityRepository.countActiveSpecificities();
        stats.put("totalSpecificities", totalSpecificities);

        // Statistiques par niveau d'alerte
        List<Object[]> alerteStats = patientSpecificityRepository.getSpecificitiesByNiveauAlerte();
        Map<String, Long> alerteMap = alerteStats.stream()
                .collect(Collectors.toMap(
                        arr -> (String) arr[0],
                        arr -> (Long) arr[1]
                ));
        stats.put("byNiveauAlerte", alerteMap);

        // Statistiques par catégorie
        List<Object[]> categoryStats = patientSpecificityRepository.getSpecificitiesByCategory();
        Map<String, Long> categoryMap = categoryStats.stream()
                .collect(Collectors.toMap(
                        arr -> (String) arr[0],
                        arr -> (Long) arr[1]
                ));
        stats.put("byCategory", categoryMap);

        // Spécificités critiques
        List<PatientSpecificity> criticalSpecificities = patientSpecificityRepository.findCriticalSpecificities();
        stats.put("criticalCount", criticalSpecificities.size());

        // Spécificités nécessitant du temps supplémentaire
        List<PatientSpecificity> extraTimeSpecificities = patientSpecificityRepository.findRequiringExtraTime();
        stats.put("extraTimeCount", extraTimeSpecificities.size());

        return stats;
    }
}