package com.lims.referential.service;

import com.lims.referential.entity.Mutuelle;
import com.lims.referential.repository.MutuelleRepository;
import com.lims.referential.dto.request.MutuelleRequestDTO;
import com.lims.referential.dto.response.MutuelleResponseDTO;
import com.lims.referential.dto.common.PagedResponseDTO;
import com.lims.referential.exception.ResourceNotFoundException;
import com.lims.referential.mapper.MutuelleMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class MutuelleService {

    private final MutuelleRepository mutuelleRepository;
    private final MutuelleMapper mutuelleMapper;

    @Cacheable(value = "mutuelles", key = "'all-' + #pageable.pageNumber + '-' + #pageable.pageSize")
    public PagedResponseDTO<MutuelleResponseDTO> findAll(Pageable pageable) {
        log.debug("Récupération de toutes les mutuelles - page: {}, size: {}", pageable.getPageNumber(), pageable.getPageSize());

        Page<Mutuelle> mutuellePage = mutuelleRepository.findAll(pageable);
        List<MutuelleResponseDTO> mutuellesDTOs = mutuellePage.getContent()
                .stream()
                .map(mutuelleMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<MutuelleResponseDTO>builder()
                .content(mutuellesDTOs)
                .page(mutuellePage.getNumber())
                .size(mutuellePage.getSize())
                .totalElements(mutuellePage.getTotalElements())
                .totalPages(mutuellePage.getTotalPages())
                .first(mutuellePage.isFirst())
                .last(mutuellePage.isLast())
                .empty(mutuellePage.isEmpty())
                .build();
    }

    @Cacheable(value = "mutuelles", key = "#id")
    public MutuelleResponseDTO findById(UUID id) {
        log.debug("Recherche de la mutuelle avec l'ID: {}", id);

        Mutuelle mutuelle = mutuelleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Mutuelle non trouvée avec l'ID: " + id));

        return mutuelleMapper.toResponseDTO(mutuelle);
    }

    @Cacheable(value = "mutuelles", key = "'search-' + #searchTerm + '-' + #pageable.pageNumber")
    public PagedResponseDTO<MutuelleResponseDTO> search(String searchTerm, Pageable pageable) {
        log.debug("Recherche de mutuelles avec le terme: {}", searchTerm);

        Page<Mutuelle> mutuellePage = mutuelleRepository.searchByTerm(searchTerm, pageable);
        List<MutuelleResponseDTO> mutuellesDTOs = mutuellePage.getContent()
                .stream()
                .map(mutuelleMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<MutuelleResponseDTO>builder()
                .content(mutuellesDTOs)
                .page(mutuellePage.getNumber())
                .size(mutuellePage.getSize())
                .totalElements(mutuellePage.getTotalElements())
                .totalPages(mutuellePage.getTotalPages())
                .first(mutuellePage.isFirst())
                .last(mutuellePage.isLast())
                .empty(mutuellePage.isEmpty())
                .build();
    }

    @Cacheable(value = "mutuelles", key = "'taux-' + #mutuelleId + '-' + #analyseCodes.hashCode()")
    public Map<String, Object> getTauxPriseEnCharge(UUID mutuelleId, List<String> analyseCodes) {
        log.debug("Calcul des taux de prise en charge pour la mutuelle: {} et les analyses: {}", mutuelleId, analyseCodes);

        Mutuelle mutuelle = mutuelleRepository.findById(mutuelleId)
                .orElseThrow(() -> new ResourceNotFoundException("Mutuelle non trouvée avec l'ID: " + mutuelleId));

        BigDecimal tauxBase = mutuelle.getTauxBaseRemboursement();
        List<Mutuelle.AnalyseCouverture> analysesCouvertes = mutuelle.getAnalysesCouvertes();

        Map<String, BigDecimal> tauxParAnalyse = analyseCodes.stream()
                .collect(java.util.stream.Collectors.toMap(
                        code -> code,
                        code -> analysesCouvertes.stream()
                                .filter(ac -> ac.getCodeNabm().equals(code))
                                .findFirst()
                                .map(Mutuelle.AnalyseCouverture::getTauxRemboursement)
                                .orElse(tauxBase)
                ));

        return Map.of(
                "mutuelle", mutuelle.getNom(),
                "tauxBase", tauxBase,
                "tauxParAnalyse", tauxParAnalyse,
                "tiersPayant", mutuelle.getTiersPayant() != null ? mutuelle.getTiersPayant() : false
        );
    }

    @Transactional
    @CacheEvict(value = "mutuelles", allEntries = true)
    public MutuelleResponseDTO create(MutuelleRequestDTO requestDTO) {
        log.info("Création d'une nouvelle mutuelle: {}", requestDTO.getNom());

        Mutuelle mutuelle = mutuelleMapper.toEntity(requestDTO);
        Mutuelle savedMutuelle = mutuelleRepository.save(mutuelle);

        log.info("Mutuelle créée avec succès - ID: {}", savedMutuelle.getId());
        return mutuelleMapper.toResponseDTO(savedMutuelle);
    }

    @Transactional
    @CacheEvict(value = "mutuelles", allEntries = true)
    public MutuelleResponseDTO update(UUID id, MutuelleRequestDTO requestDTO) {
        log.info("Mise à jour de la mutuelle avec l'ID: {}", id);

        Mutuelle existingMutuelle = mutuelleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Mutuelle non trouvée avec l'ID: " + id));

        mutuelleMapper.updateEntityFromDTO(requestDTO, existingMutuelle);
        Mutuelle updatedMutuelle = mutuelleRepository.save(existingMutuelle);

        log.info("Mutuelle mise à jour avec succès - ID: {}", updatedMutuelle.getId());
        return mutuelleMapper.toResponseDTO(updatedMutuelle);
    }

    @Transactional
    @CacheEvict(value = "mutuelles", allEntries = true)
    public void delete(UUID id) {
        log.info("Suppression de la mutuelle avec l'ID: {}", id);

        Mutuelle mutuelle = mutuelleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Mutuelle non trouvée avec l'ID: " + id));

        mutuelle.markAsDeleted();
        mutuelleRepository.save(mutuelle);

        log.info("Mutuelle supprimée avec succès - ID: {}", id);
    }

    @Cacheable(value = "mutuelles", key = "'stats'")
    public Map<String, Object> getStatistics() {
        log.debug("Récupération des statistiques des mutuelles");

        long totalMutuelles = mutuelleRepository.count();

        return Map.of(
                "totalMutuelles", totalMutuelles
        );
    }
}