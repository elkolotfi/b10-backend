package com.lims.laboratory.service;

import com.lims.laboratory.dto.request.LaboratoireRequestDTO;
import com.lims.laboratory.dto.request.LaboratoireSearchDTO;
import com.lims.laboratory.dto.response.LaboratoireResponseDTO;
import com.lims.laboratory.dto.response.PagedResponseDTO;
import com.lims.laboratory.entity.Laboratoire;
import com.lims.laboratory.entity.Laboratoire.TypeLaboratoire;
import com.lims.laboratory.exception.LaboratoireNotFoundException;
import com.lims.laboratory.exception.LaboratoireDuplicateException;
import com.lims.laboratory.mapper.LaboratoireMapper;
import com.lims.laboratory.repository.LaboratoireRepository;
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
import java.util.stream.Collectors;

/**
 * Service pour la gestion des laboratoires
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class LaboratoireService {

    private final LaboratoireRepository laboratoireRepository;
    private final LaboratoireMapper laboratoireMapper;

    // === Opérations CRUD ===

    /**
     * Crée un nouveau laboratoire
     */
    public LaboratoireResponseDTO createLaboratoire(LaboratoireRequestDTO requestDTO) {
        log.info("Création d'un nouveau laboratoire: {}", requestDTO.getNomCommercial());

        // Vérification des doublons
        validateUniqueFields(requestDTO, null);

        // Conversion et sauvegarde
        Laboratoire laboratoire = laboratoireMapper.toEntity(requestDTO);
        laboratoire = laboratoireRepository.save(laboratoire);

        log.info("Laboratoire créé avec l'ID: {}", laboratoire.getId());
        return laboratoireMapper.toResponseDTO(laboratoire);
    }

    /**
     * Récupère un laboratoire par son ID
     */
    @Transactional(readOnly = true)
    public LaboratoireResponseDTO getLaboratoireById(UUID id) {
        log.debug("Recherche du laboratoire avec l'ID: {}", id);

        Laboratoire laboratoire = findLaboratoireById(id);
        return laboratoireMapper.toResponseDTO(laboratoire);
    }

    /**
     * Met à jour un laboratoire existant
     */
    public LaboratoireResponseDTO updateLaboratoire(UUID id, LaboratoireRequestDTO requestDTO) {
        log.info("Mise à jour du laboratoire avec l'ID: {}", id);

        Laboratoire laboratoire = findLaboratoireById(id);

        // Vérification des doublons (en excluant le laboratoire actuel)
        validateUniqueFields(requestDTO, id);

        // Mise à jour et sauvegarde
        laboratoireMapper.updateEntity(requestDTO, laboratoire);
        laboratoire = laboratoireRepository.save(laboratoire);

        log.info("Laboratoire mis à jour avec l'ID: {}", laboratoire.getId());
        return laboratoireMapper.toResponseDTO(laboratoire);
    }

    /**
     * Supprime un laboratoire
     */
    public void deleteLaboratoire(UUID id) {
        log.info("Suppression du laboratoire avec l'ID: {}", id);

        Laboratoire laboratoire = findLaboratoireById(id);
        laboratoireRepository.delete(laboratoire);

        log.info("Laboratoire supprimé avec l'ID: {}", id);
    }

    /**
     * Active ou désactive un laboratoire
     */
    public LaboratoireResponseDTO toggleActivation(UUID id, boolean actif) {
        log.info("Modification du statut du laboratoire {} : {}", id, actif ? "activation" : "désactivation");

        Laboratoire laboratoire = findLaboratoireById(id);
        laboratoire.setActif(actif);
        laboratoire = laboratoireRepository.save(laboratoire);

        log.info("Statut du laboratoire {} modifié : {}", id, actif);
        return laboratoireMapper.toResponseDTO(laboratoire);
    }

    // === Recherches et listages ===

    /**
     * Recherche paginée de laboratoires avec critères
     */
    @Transactional(readOnly = true)
    public PagedResponseDTO<LaboratoireResponseDTO> searchLaboratoires(
            LaboratoireSearchDTO searchDTO,
            int page,
            int size,
            String sortBy,
            String sortDirection) {

        log.debug("Recherche de laboratoires avec critères: {}", searchDTO);

        // Configuration du tri
        Sort.Direction direction = Sort.Direction.fromString(sortDirection);
        Sort sort = Sort.by(direction, sortBy);
        Pageable pageable = PageRequest.of(page, size, sort);

        // Recherche avec critères
        Page<Laboratoire> laboratoirePage = laboratoireRepository.findWithCriteria(
                searchDTO.getSearchTerm(),
                searchDTO.getTypeLaboratoire(),
                searchDTO.getActif(),
                searchDTO.getSiret(),
                searchDTO.getNumeroFiness(),
                pageable
        );

        // Conversion des résultats
        List<LaboratoireResponseDTO> content = laboratoireMapper.toResponseDTOList(laboratoirePage.getContent());

        return PagedResponseDTO.<LaboratoireResponseDTO>builder()
                .content(content)
                .page(laboratoirePage.getNumber())
                .size(laboratoirePage.getSize())
                .totalElements(laboratoirePage.getTotalElements())
                .totalPages(laboratoirePage.getTotalPages())
                .first(laboratoirePage.isFirst())
                .last(laboratoirePage.isLast())
                .hasNext(laboratoirePage.hasNext())
                .hasPrevious(laboratoirePage.hasPrevious())
                .build();
    }

    /**
     * Récupère tous les laboratoires actifs (sans pagination)
     */
    @Transactional(readOnly = true)
    public List<LaboratoireResponseDTO> getAllActiveLaboratoires() {
        log.debug("Récupération de tous les laboratoires actifs");

        List<Laboratoire> laboratoires = laboratoireRepository.findByActifTrue();
        return laboratoireMapper.toResponseDTOList(laboratoires);
    }

    /**
     * Récupère les laboratoires par type
     */
    @Transactional(readOnly = true)
    public List<LaboratoireResponseDTO> getLaboratoiresByType(TypeLaboratoire type) {
        log.debug("Récupération des laboratoires de type: {}", type);

        List<Laboratoire> laboratoires = laboratoireRepository.findByTypeLaboratoireAndActif(type, true);
        return laboratoireMapper.toResponseDTOList(laboratoires);
    }

    // === Recherches spécifiques ===

    /**
     * Recherche un laboratoire par SIRET
     */
    @Transactional(readOnly = true)
    public LaboratoireResponseDTO findBySiret(String siret) {
        log.debug("Recherche du laboratoire avec SIRET: {}", siret);

        return laboratoireRepository.findBySiret(siret)
                .map(laboratoireMapper::toResponseDTO)
                .orElseThrow(() -> new LaboratoireNotFoundException("Aucun laboratoire trouvé avec le SIRET: " + siret));
    }

    /**
     * Recherche un laboratoire par numéro FINESS
     */
    @Transactional(readOnly = true)
    public LaboratoireResponseDTO findByNumeroFiness(String numeroFiness) {
        log.debug("Recherche du laboratoire avec numéro FINESS: {}", numeroFiness);

        return laboratoireRepository.findByNumeroFiness(numeroFiness)
                .map(laboratoireMapper::toResponseDTO)
                .orElseThrow(() -> new LaboratoireNotFoundException("Aucun laboratoire trouvé avec le numéro FINESS: " + numeroFiness));
    }

    /**
     * Recherche un laboratoire par code laboratoire
     */
    @Transactional(readOnly = true)
    public LaboratoireResponseDTO findByCodeLaboratoire(String codeLaboratoire) {
        log.debug("Recherche du laboratoire avec code: {}", codeLaboratoire);

        return laboratoireRepository.findByCodeLaboratoire(codeLaboratoire)
                .map(laboratoireMapper::toResponseDTO)
                .orElseThrow(() -> new LaboratoireNotFoundException("Aucun laboratoire trouvé avec le code: " + codeLaboratoire));
    }

    // === Statistiques ===

    /**
     * Récupère les statistiques des laboratoires
     */
    @Transactional(readOnly = true)
    public Map<String, Object> getStatistiques() {
        log.debug("Génération des statistiques des laboratoires");

        long totalActifs = laboratoireRepository.countByActifTrue();
        long totalGlobal = laboratoireRepository.count();

        // Statistiques par type
        List<Object[]> statsByType = laboratoireRepository.getStatistiquesByType();
        Map<String, Long> repartitionByType = statsByType.stream()
                .collect(Collectors.toMap(
                        row -> ((TypeLaboratoire) row[0]).name(),
                        row -> (Long) row[1]
                ));

        return Map.of(
                "totalLaboratoires", totalGlobal,
                "laboratoiresActifs", totalActifs,
                "laboratoiresInactifs", totalGlobal - totalActifs,
                "repartitionParType", repartitionByType
        );
    }

    // === Méthodes utilitaires ===

    /**
     * Trouve un laboratoire par ID ou lance une exception
     */
    private Laboratoire findLaboratoireById(UUID id) {
        return laboratoireRepository.findById(id)
                .orElseThrow(() -> new LaboratoireNotFoundException("Laboratoire non trouvé avec l'ID: " + id));
    }

    /**
     * Valide l'unicité des champs uniques
     */
    private void validateUniqueFields(LaboratoireRequestDTO requestDTO, UUID excludeId) {
        // Vérification SIRET
        if (StringUtils.hasText(requestDTO.getSiret())) {
            boolean siretExists = (excludeId != null)
                    ? laboratoireRepository.existsBySiretAndIdNot(requestDTO.getSiret(), excludeId)
                    : laboratoireRepository.findBySiret(requestDTO.getSiret()).isPresent();

            if (siretExists) {
                throw new LaboratoireDuplicateException("Un laboratoire existe déjà avec le SIRET: " + requestDTO.getSiret());
            }
        }

        // Vérification numéro FINESS
        if (StringUtils.hasText(requestDTO.getNumeroFiness())) {
            boolean finessExists = (excludeId != null)
                    ? laboratoireRepository.existsByNumeroFinessAndIdNot(requestDTO.getNumeroFiness(), excludeId)
                    : laboratoireRepository.findByNumeroFiness(requestDTO.getNumeroFiness()).isPresent();

            if (finessExists) {
                throw new LaboratoireDuplicateException("Un laboratoire existe déjà avec le numéro FINESS: " + requestDTO.getNumeroFiness());
            }
        }

        // Vérification code laboratoire
        if (StringUtils.hasText(requestDTO.getCodeLaboratoire())) {
            boolean codeExists = (excludeId != null)
                    ? laboratoireRepository.existsByCodeLaboratoireAndIdNot(requestDTO.getCodeLaboratoire(), excludeId)
                    : laboratoireRepository.findByCodeLaboratoire(requestDTO.getCodeLaboratoire()).isPresent();

            if (codeExists) {
                throw new LaboratoireDuplicateException("Un laboratoire existe déjà avec le code: " + requestDTO.getCodeLaboratoire());
            }
        }
    }
}