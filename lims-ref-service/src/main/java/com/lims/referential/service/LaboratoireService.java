package com.lims.referential.service;

import com.lims.referential.entity.Laboratoire;
import com.lims.referential.repository.LaboratoireRepository;
import com.lims.referential.dto.request.LaboratoireRequestDTO;
import com.lims.referential.dto.response.LaboratoireResponseDTO;
import com.lims.referential.dto.common.PagedResponseDTO;
import com.lims.referential.exception.ResourceNotFoundException;
import com.lims.referential.mapper.LaboratoireMapper;
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
public class LaboratoireService {

    private final LaboratoireRepository laboratoireRepository;
    private final LaboratoireMapper laboratoireMapper;

    @Cacheable(value = "laboratoires", key = "'all-' + #pageable.pageNumber + '-' + #pageable.pageSize")
    public PagedResponseDTO<LaboratoireResponseDTO> findAll(Pageable pageable) {
        log.debug("Récupération de tous les laboratoires - page: {}, size: {}", pageable.getPageNumber(), pageable.getPageSize());

        Page<Laboratoire> laboratoirePage = laboratoireRepository.findAll(pageable);
        List<LaboratoireResponseDTO> laboratoiresDTOs = laboratoirePage.getContent()
                .stream()
                .map(laboratoireMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<LaboratoireResponseDTO>builder()
                .content(laboratoiresDTOs)
                .page(laboratoirePage.getNumber())
                .size(laboratoirePage.getSize())
                .totalElements(laboratoirePage.getTotalElements())
                .totalPages(laboratoirePage.getTotalPages())
                .first(laboratoirePage.isFirst())
                .last(laboratoirePage.isLast())
                .empty(laboratoirePage.isEmpty())
                .build();
    }

    @Cacheable(value = "laboratoires", key = "#id")
    public LaboratoireResponseDTO findById(UUID id) {
        log.debug("Recherche du laboratoire avec l'ID: {}", id);

        Laboratoire laboratoire = laboratoireRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Laboratoire non trouvé avec l'ID: " + id));

        return laboratoireMapper.toResponseDTO(laboratoire);
    }

    @Cacheable(value = "laboratoires", key = "'search-' + #searchTerm + '-' + #pageable.pageNumber")
    public PagedResponseDTO<LaboratoireResponseDTO> search(String searchTerm, Pageable pageable) {
        log.debug("Recherche de laboratoires avec le terme: {}", searchTerm);

        Page<Laboratoire> laboratoirePage = laboratoireRepository.searchByTerm(searchTerm, pageable);
        List<LaboratoireResponseDTO> laboratoiresDTOs = laboratoirePage.getContent()
                .stream()
                .map(laboratoireMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<LaboratoireResponseDTO>builder()
                .content(laboratoiresDTOs)
                .page(laboratoirePage.getNumber())
                .size(laboratoirePage.getSize())
                .totalElements(laboratoirePage.getTotalElements())
                .totalPages(laboratoirePage.getTotalPages())
                .first(laboratoirePage.isFirst())
                .last(laboratoirePage.isLast())
                .empty(laboratoirePage.isEmpty())
                .build();
    }

    @Cacheable(value = "laboratoires", key = "'geoloc-' + #latitude + '-' + #longitude + '-' + #radius")
    public List<LaboratoireResponseDTO> searchByGeolocation(BigDecimal latitude, BigDecimal longitude, Integer radius) {
        log.debug("Recherche géographique - lat: {}, lon: {}, rayon: {}km", latitude, longitude, radius);

        List<Laboratoire> laboratoires = laboratoireRepository.findByGeolocation(latitude, longitude, radius);

        return laboratoires.stream()
                .map(laboratoireMapper::toResponseDTO)
                .toList();
    }

    @Cacheable(value = "laboratoires", key = "'analyses-' + #laboratoireId")
    public List<String> getAnalysesDisponibles(UUID laboratoireId) {
        log.debug("Récupération des analyses disponibles pour le laboratoire: {}", laboratoireId);

        Laboratoire laboratoire = laboratoireRepository.findById(laboratoireId)
                .orElseThrow(() -> new ResourceNotFoundException("Laboratoire non trouvé avec l'ID: " + laboratoireId));

        return laboratoire.getAnalysesDisponibles();
    }

    @Transactional
    @CacheEvict(value = "laboratoires", allEntries = true)
    public LaboratoireResponseDTO create(LaboratoireRequestDTO requestDTO) {
        log.info("Création d'un nouveau laboratoire: {}", requestDTO.getNom());

        Laboratoire laboratoire = laboratoireMapper.toEntity(requestDTO);
        Laboratoire savedLaboratoire = laboratoireRepository.save(laboratoire);

        log.info("Laboratoire créé avec succès - ID: {}", savedLaboratoire.getId());
        return laboratoireMapper.toResponseDTO(savedLaboratoire);
    }

    @Transactional
    @CacheEvict(value = "laboratoires", allEntries = true)
    public LaboratoireResponseDTO update(UUID id, LaboratoireRequestDTO requestDTO) {
        log.info("Mise à jour du laboratoire avec l'ID: {}", id);

        Laboratoire existingLaboratoire = laboratoireRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Laboratoire non trouvé avec l'ID: " + id));

        laboratoireMapper.updateEntityFromDTO(requestDTO, existingLaboratoire);
        Laboratoire updatedLaboratoire = laboratoireRepository.save(existingLaboratoire);

        log.info("Laboratoire mis à jour avec succès - ID: {}", updatedLaboratoire.getId());
        return laboratoireMapper.toResponseDTO(updatedLaboratoire);
    }

    @Transactional
    @CacheEvict(value = "laboratoires", allEntries = true)
    public void delete(UUID id) {
        log.info("Suppression du laboratoire avec l'ID: {}", id);

        Laboratoire laboratoire = laboratoireRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Laboratoire non trouvé avec l'ID: " + id));

        laboratoire.markAsDeleted();
        laboratoireRepository.save(laboratoire);

        log.info("Laboratoire supprimé avec succès - ID: {}", id);
    }

    @Cacheable(value = "laboratoires", key = "'stats'")
    public Map<String, Object> getStatistics() {
        log.debug("Récupération des statistiques des laboratoires");

        long totalLaboratoires = laboratoireRepository.count();

        return Map.of(
                "totalLaboratoires", totalLaboratoires
        );
    }
}