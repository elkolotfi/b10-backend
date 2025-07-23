package com.lims.referential.service;

import com.lims.referential.entity.SpecificityCategory;
import com.lims.referential.repository.SpecificityCategoryRepository;
import com.lims.referential.repository.PatientSpecificityRepository;
import com.lims.referential.dto.response.SpecificityCategoryResponseDTO;
import com.lims.referential.exception.ResourceNotFoundException;
import com.lims.referential.mapper.SpecificityCategoryMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class SpecificityCategoryService {

    private final SpecificityCategoryRepository specificityCategoryRepository;
    private final PatientSpecificityRepository patientSpecificityRepository;
    private final SpecificityCategoryMapper specificityCategoryMapper;

    /**
     * Récupère toutes les catégories actives
     */
    @Cacheable(value = "specificity-categories", key = "'all-active'")
    public List<SpecificityCategoryResponseDTO> findAllActive() {
        log.debug("Récupération de toutes les catégories actives");

        List<SpecificityCategory> categories = specificityCategoryRepository.findAllByActifTrueOrderByOrdreAffichage();

        return categories.stream()
                .map(specificityCategoryMapper::toResponseDTO)
                .toList();
    }

    /**
     * Récupère une catégorie par son ID
     */
    @Cacheable(value = "specificity-categories", key = "#id")
    public SpecificityCategoryResponseDTO findById(String id) {
        log.debug("Recherche de la catégorie avec l'ID: {}", id);

        SpecificityCategory category = specificityCategoryRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Catégorie de spécificité non trouvée avec l'ID: " + id));

        return specificityCategoryMapper.toResponseDTO(category);
    }

    /**
     * Récupère les statistiques des catégories
     */
    @Cacheable(value = "specificity-categories", key = "'statistics'")
    public Map<String, Object> getStatistics() {
        log.debug("Génération des statistiques des catégories");

        Map<String, Object> stats = new HashMap<>();

        // Nombre total de catégories actives
        long totalCategories = specificityCategoryRepository.count();
        stats.put("totalCategories", totalCategories);

        // Statistiques par catégorie avec nombre de spécificités
        List<Object[]> categoryStats = patientSpecificityRepository.getSpecificitiesByCategory();
        Map<String, Long> categorySpecificityCount = categoryStats.stream()
                .collect(Collectors.toMap(
                        arr -> (String) arr[0],
                        arr -> (Long) arr[1]
                ));
        stats.put("specificitiesPerCategory", categorySpecificityCount);

        // Catégories les plus utilisées
        List<SpecificityCategory> allCategories = specificityCategoryRepository.findAllByActifTrueOrderByOrdreAffichage();
        List<Map<String, Object>> categoryDetails = allCategories.stream()
                .map(category -> {
                    Map<String, Object> details = new HashMap<>();
                    details.put("id", category.getId());
                    details.put("nom", category.getNom());
                    details.put("specificityCount", categorySpecificityCount.getOrDefault(category.getId(), 0L));
                    return details;
                })
                .sorted((a, b) -> Long.compare((Long) b.get("specificityCount"), (Long) a.get("specificityCount")))
                .toList();

        stats.put("categoryDetails", categoryDetails);

        return stats;
    }

    /**
     * Vérifie si une catégorie existe par son nom
     */
    public boolean existsByNom(String nom) {
        return specificityCategoryRepository.findByNomAndActifTrue(nom).isPresent();
    }
}