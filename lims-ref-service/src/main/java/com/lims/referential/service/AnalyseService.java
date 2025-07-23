package com.lims.referential.service;

import com.lims.referential.enums.analyses.CategorieAnalyse;
import com.lims.referential.entity.Analyse;
import com.lims.referential.repository.AnalyseRepository;
import com.lims.referential.dto.response.PagedResponseDTO;
import com.lims.referential.dto.request.AnalyseRequestDTO;
import com.lims.referential.dto.response.AnalyseResponseDTO;
import com.lims.referential.exception.ResourceNotFoundException;
import com.lims.referential.mapper.AnalyseMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class AnalyseService {

    private final AnalyseRepository analyseRepository;
    private final AnalyseMapper analyseMapper;

    /**
     * Récupère toutes les analyses avec pagination
     */
    @Cacheable(value = "analyses", key = "'all-' + #pageable.pageNumber + '-' + #pageable.pageSize + '-' + #pageable.sort.toString()")
    public PagedResponseDTO<AnalyseResponseDTO> findAll(Pageable pageable) {
        log.debug("Récupération de toutes les analyses - page: {}, size: {}", pageable.getPageNumber(), pageable.getPageSize());

        Page<Analyse> analysePage = analyseRepository.findAll(pageable);
        List<AnalyseResponseDTO> analysesDTOs = analysePage.getContent()
                .stream()
                .map(analyseMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<AnalyseResponseDTO>builder()
                .content(analysesDTOs)
                .page(analysePage.getNumber())
                .size(analysePage.getSize())
                .totalElements(analysePage.getTotalElements())
                .totalPages(analysePage.getTotalPages())
                .first(analysePage.isFirst())
                .last(analysePage.isLast())
                .empty(analysePage.isEmpty())
                .build();
    }

    /**
     * Recherche une analyse par ID
     */
    @Cacheable(value = "analyses", key = "#id")
    public AnalyseResponseDTO findById(UUID id) {
        log.debug("Recherche de l'analyse avec l'ID: {}", id);

        Analyse analyse = analyseRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Analyse non trouvée avec l'ID: " + id));

        return analyseMapper.toResponseDTO(analyse);
    }

    /**
     * Recherche par code NABM
     */
    @Cacheable(value = "analyses", key = "'nabm-' + #codeNabm")
    public AnalyseResponseDTO findByCodeNabm(String codeNabm) {
        log.debug("Recherche de l'analyse avec le code NABM: {}", codeNabm);

        Analyse analyse = analyseRepository.findByCodeNabmAndActifTrue(codeNabm)
                .orElseThrow(() -> new ResourceNotFoundException("Analyse non trouvée avec le code NABM: " + codeNabm));

        return analyseMapper.toResponseDTO(analyse);
    }

    /**
     * Recherche textuelle
     */
    @Cacheable(value = "analyses", key = "'search-' + #searchTerm + '-' + #pageable.pageNumber + '-' + #pageable.pageSize")
    public PagedResponseDTO<AnalyseResponseDTO> search(String searchTerm, Pageable pageable) {
        log.debug("Recherche d'analyses avec le terme: {}", searchTerm);

        Page<Analyse> analysePage = analyseRepository.searchByTerm(searchTerm, pageable);
        List<AnalyseResponseDTO> analysesDTOs = analysePage.getContent()
                .stream()
                .map(analyseMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<AnalyseResponseDTO>builder()
                .content(analysesDTOs)
                .page(analysePage.getNumber())
                .size(analysePage.getSize())
                .totalElements(analysePage.getTotalElements())
                .totalPages(analysePage.getTotalPages())
                .first(analysePage.isFirst())
                .last(analysePage.isLast())
                .empty(analysePage.isEmpty())
                .build();
    }

    /**
     * Auto-complétion
     */
    @Cacheable(value = "analyses", key = "'suggest-' + #prefix")
    public List<AnalyseResponseDTO> suggest(String prefix) {
        log.debug("Auto-complétion pour le préfixe: {}", prefix);

        Pageable pageable = PageRequest.of(0, 10, Sort.by("libelle"));
        List<Analyse> suggestions = analyseRepository.findSuggestions(prefix, pageable);

        return suggestions.stream()
                .map(analyseMapper::toResponseDTO)
                .toList();
    }

    /**
     * Filtrage multi-critères
     */
    public PagedResponseDTO<AnalyseResponseDTO> findWithFilters(
            CategorieAnalyse categorie, String sousCategorie, Boolean actif, Pageable pageable) {

        log.debug("Filtrage des analyses - catégorie: {}, sous-catégorie: {}, actif: {}",
                categorie, sousCategorie, actif);

        Page<Analyse> analysePage = analyseRepository.findWithFilters(categorie, sousCategorie, actif, pageable);
        List<AnalyseResponseDTO> analysesDTOs = analysePage.getContent()
                .stream()
                .map(analyseMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<AnalyseResponseDTO>builder()
                .content(analysesDTOs)
                .page(analysePage.getNumber())
                .size(analysePage.getSize())
                .totalElements(analysePage.getTotalElements())
                .totalPages(analysePage.getTotalPages())
                .first(analysePage.isFirst())
                .last(analysePage.isLast())
                .empty(analysePage.isEmpty())
                .build();
    }

    /**
     * Crée une nouvelle analyse
     */
    @Transactional
    @CacheEvict(value = "analyses", allEntries = true)
    public AnalyseResponseDTO create(AnalyseRequestDTO requestDTO) {
        log.info("Création d'une nouvelle analyse avec le code NABM: {}", requestDTO.getCodeNabm());

        // Vérifier l'unicité du code NABM
        if (analyseRepository.findByCodeNabmAndActifTrue(requestDTO.getCodeNabm()).isPresent()) {
            throw new IllegalArgumentException("Une analyse existe déjà avec le code NABM: " + requestDTO.getCodeNabm());
        }

        Analyse analyse = analyseMapper.toEntity(requestDTO);
        Analyse savedAnalyse = analyseRepository.save(analyse);

        log.info("Analyse créée avec succès - ID: {}, Code NABM: {}", savedAnalyse.getId(), savedAnalyse.getCodeNabm());
        return analyseMapper.toResponseDTO(savedAnalyse);
    }

    /**
     * Met à jour une analyse
     */
    @Transactional
    @CacheEvict(value = "analyses", allEntries = true)
    public AnalyseResponseDTO update(UUID id, AnalyseRequestDTO requestDTO) {
        log.info("Mise à jour de l'analyse avec l'ID: {}", id);

        Analyse existingAnalyse = analyseRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Analyse non trouvée avec l'ID: " + id));

        // Vérifier l'unicité du code NABM si modifié
        if (!existingAnalyse.getCodeNabm().equals(requestDTO.getCodeNabm())) {
            if (analyseRepository.findByCodeNabmAndActifTrue(requestDTO.getCodeNabm()).isPresent()) {
                throw new IllegalArgumentException("Une analyse existe déjà avec le code NABM: " + requestDTO.getCodeNabm());
            }
        }

        analyseMapper.updateEntityFromDTO(requestDTO, existingAnalyse);
        Analyse updatedAnalyse = analyseRepository.save(existingAnalyse);

        log.info("Analyse mise à jour avec succès - ID: {}", updatedAnalyse.getId());
        return analyseMapper.toResponseDTO(updatedAnalyse);
    }

    /**
     * Suppression logique d'une analyse
     */
    @Transactional
    @CacheEvict(value = "analyses", allEntries = true)
    public void delete(UUID id) {
        log.info("Suppression de l'analyse avec l'ID: {}", id);

        Analyse analyse = analyseRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Analyse non trouvée avec l'ID: " + id));

        analyse.markAsDeleted();
        analyseRepository.save(analyse);

        log.info("Analyse supprimée avec succès - ID: {}", id);
    }

    /**
     * Statistiques des analyses
     */
    @Cacheable(value = "analyses", key = "'stats'")
    public Map<String, Object> getStatistics() {
        log.debug("Récupération des statistiques des analyses");

        long totalAnalyses = analyseRepository.countActiveAnalyses();
        List<Object[]> analysesByCategory = analyseRepository.getAnalysesByCategory();

        Map<String, Long> categoriesCount = analysesByCategory.stream()
                .collect(java.util.stream.Collectors.toMap(
                        obj -> obj[0].toString(),
                        obj -> (Long) obj[1]
                ));

        return Map.of(
                "totalAnalyses", totalAnalyses,
                "analysesByCategory", categoriesCount
        );
    }
}