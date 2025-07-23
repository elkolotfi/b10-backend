package com.lims.referential.service;

import com.lims.referential.entity.Medecin;
import com.lims.referential.repository.MedecinRepository;
import com.lims.referential.dto.request.MedecinRequestDTO;
import com.lims.referential.dto.response.MedecinResponseDTO;
import com.lims.referential.dto.common.PagedResponseDTO;
import com.lims.referential.exception.ResourceNotFoundException;
import com.lims.referential.mapper.MedecinMapper;
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
public class MedecinService {

    private final MedecinRepository medecinRepository;
    private final MedecinMapper medecinMapper;

    @Cacheable(value = "medecins", key = "'all-' + #pageable.pageNumber + '-' + #pageable.pageSize + '-' + #pageable.sort.toString()")
    public PagedResponseDTO<MedecinResponseDTO> findAll(Pageable pageable) {
        log.debug("Récupération de tous les médecins - page: {}, size: {}", pageable.getPageNumber(), pageable.getPageSize());

        Page<Medecin> medecinPage = medecinRepository.findAll(pageable);
        List<MedecinResponseDTO> medecinsDTOs = medecinPage.getContent()
                .stream()
                .map(medecinMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<MedecinResponseDTO>builder()
                .content(medecinsDTOs)
                .page(medecinPage.getNumber())
                .size(medecinPage.getSize())
                .totalElements(medecinPage.getTotalElements())
                .totalPages(medecinPage.getTotalPages())
                .first(medecinPage.isFirst())
                .last(medecinPage.isLast())
                .empty(medecinPage.isEmpty())
                .build();
    }

    @Cacheable(value = "medecins", key = "#id")
    public MedecinResponseDTO findById(UUID id) {
        log.debug("Recherche du médecin avec l'ID: {}", id);

        Medecin medecin = medecinRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Médecin non trouvé avec l'ID: " + id));

        return medecinMapper.toResponseDTO(medecin);
    }

    @Cacheable(value = "medecins", key = "'rpps-' + #numeroRpps")
    public MedecinResponseDTO findByNumeroRpps(String numeroRpps) {
        log.debug("Recherche du médecin avec le numéro RPPS: {}", numeroRpps);

        Medecin medecin = medecinRepository.findByNumeroRppsAndActifTrue(numeroRpps)
                .orElseThrow(() -> new ResourceNotFoundException("Médecin non trouvé avec le numéro RPPS: " + numeroRpps));

        return medecinMapper.toResponseDTO(medecin);
    }

    @Cacheable(value = "medecins", key = "'search-' + #searchTerm + '-' + #pageable.pageNumber + '-' + #pageable.pageSize")
    public PagedResponseDTO<MedecinResponseDTO> search(String searchTerm, Pageable pageable) {
        log.debug("Recherche de médecins avec le terme: {}", searchTerm);

        Page<Medecin> medecinPage = medecinRepository.searchByTerm(searchTerm, pageable);
        List<MedecinResponseDTO> medecinsDTOs = medecinPage.getContent()
                .stream()
                .map(medecinMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<MedecinResponseDTO>builder()
                .content(medecinsDTOs)
                .page(medecinPage.getNumber())
                .size(medecinPage.getSize())
                .totalElements(medecinPage.getTotalElements())
                .totalPages(medecinPage.getTotalPages())
                .first(medecinPage.isFirst())
                .last(medecinPage.isLast())
                .empty(medecinPage.isEmpty())
                .build();
    }

    @Cacheable(value = "medecins", key = "'suggest-' + #prefix")
    public List<MedecinResponseDTO> suggest(String prefix) {
        log.debug("Auto-complétion pour le préfixe: {}", prefix);

        Pageable pageable = PageRequest.of(0, 10, Sort.by("nom", "prenom"));
        List<Medecin> suggestions = medecinRepository.findSuggestions(prefix, pageable);

        return suggestions.stream()
                .map(medecinMapper::toResponseDTO)
                .toList();
    }

    public PagedResponseDTO<MedecinResponseDTO> findWithFilters(
            String specialite, String ville, String departement, Pageable pageable) {

        log.debug("Filtrage des médecins - spécialité: {}, ville: {}, département: {}",
                specialite, ville, departement);

        Page<Medecin> medecinPage = medecinRepository.findWithFilters(specialite, ville, departement, pageable);
        List<MedecinResponseDTO> medecinsDTOs = medecinPage.getContent()
                .stream()
                .map(medecinMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<MedecinResponseDTO>builder()
                .content(medecinsDTOs)
                .page(medecinPage.getNumber())
                .size(medecinPage.getSize())
                .totalElements(medecinPage.getTotalElements())
                .totalPages(medecinPage.getTotalPages())
                .first(medecinPage.isFirst())
                .last(medecinPage.isLast())
                .empty(medecinPage.isEmpty())
                .build();
    }

    @Transactional
    @CacheEvict(value = "medecins", allEntries = true)
    public MedecinResponseDTO create(MedecinRequestDTO requestDTO) {
        log.info("Création d'un nouveau médecin avec le numéro RPPS: {}", requestDTO.getNumeroRpps());

        if (medecinRepository.findByNumeroRppsAndActifTrue(requestDTO.getNumeroRpps()).isPresent()) {
            throw new IllegalArgumentException("Un médecin existe déjà avec le numéro RPPS: " + requestDTO.getNumeroRpps());
        }

        Medecin medecin = medecinMapper.toEntity(requestDTO);
        Medecin savedMedecin = medecinRepository.save(medecin);

        log.info("Médecin créé avec succès - ID: {}, RPPS: {}", savedMedecin.getId(), savedMedecin.getNumeroRpps());
        return medecinMapper.toResponseDTO(savedMedecin);
    }

    @Transactional
    @CacheEvict(value = "medecins", allEntries = true)
    public MedecinResponseDTO update(UUID id, MedecinRequestDTO requestDTO) {
        log.info("Mise à jour du médecin avec l'ID: {}", id);

        Medecin existingMedecin = medecinRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Médecin non trouvé avec l'ID: " + id));

        if (!existingMedecin.getNumeroRpps().equals(requestDTO.getNumeroRpps())) {
            if (medecinRepository.findByNumeroRppsAndActifTrue(requestDTO.getNumeroRpps()).isPresent()) {
                throw new IllegalArgumentException("Un médecin existe déjà avec le numéro RPPS: " + requestDTO.getNumeroRpps());
            }
        }

        medecinMapper.updateEntityFromDTO(requestDTO, existingMedecin);
        Medecin updatedMedecin = medecinRepository.save(existingMedecin);

        log.info("Médecin mis à jour avec succès - ID: {}", updatedMedecin.getId());
        return medecinMapper.toResponseDTO(updatedMedecin);
    }

    @Transactional
    @CacheEvict(value = "medecins", allEntries = true)
    public void delete(UUID id) {
        log.info("Suppression du médecin avec l'ID: {}", id);

        Medecin medecin = medecinRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Médecin non trouvé avec l'ID: " + id));

        medecin.markAsDeleted();
        medecinRepository.save(medecin);

        log.info("Médecin supprimé avec succès - ID: {}", id);
    }

    @Cacheable(value = "medecins", key = "'stats'")
    public Map<String, Object> getStatistics() {
        log.debug("Récupération des statistiques des médecins");

        long totalMedecins = medecinRepository.count();

        return Map.of(
                "totalMedecins", totalMedecins
        );
    }
}


// PatientSpecificityService.java


// ValidationService.java


// CacheService.java
