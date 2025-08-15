package com.lims.laboratory.service;

import com.lims.laboratory.dto.request.PrelevementRequestDTO;
import com.lims.laboratory.dto.request.PrelevementSearchDTO;
import com.lims.laboratory.dto.response.PagedResponseDTO;
import com.lims.laboratory.dto.response.PrelevementResponseDTO;
import com.lims.laboratory.entity.Examen;
import com.lims.laboratory.entity.LaboratoirePrelevement;
import com.lims.laboratory.entity.Laboratoire;
import com.lims.laboratory.exception.ExamenNotFoundException;
import com.lims.laboratory.exception.LaboratoireNotFoundException;
import com.lims.laboratory.exception.PrelevementNotFoundException;
import com.lims.laboratory.exception.PrelevementValidationException;
import com.lims.laboratory.mapper.PrelevementMapper;
import com.lims.laboratory.repository.ExamenRepository;
import com.lims.laboratory.repository.LaboratoireRepository;
import com.lims.laboratory.repository.PrelevementRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Service pour la gestion des prélèvements de laboratoire
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class PrelevementService {

    private final PrelevementRepository prelevementRepository;
    private final LaboratoireRepository laboratoireRepository;
    private final ExamenRepository examenRepository;
    private final PrelevementMapper prelevementMapper;

    // === OPÉRATIONS CRUD ===

    /**
     * Crée un nouveau prélèvement personnalisé pour un examen
     */
    public PrelevementResponseDTO createPrelevement(PrelevementRequestDTO requestDTO) {
        log.info("Création d'un nouveau prélèvement pour examen: {}", requestDTO.getLaboratoireExamenId());

        // Validation du laboratoire
        Laboratoire laboratoire = laboratoireRepository.findById(requestDTO.getLaboratoireId())
                .orElseThrow(() -> new LaboratoireNotFoundException(
                        "Laboratoire non trouvé: " + requestDTO.getLaboratoireId()));

        // Validation de l'examen
        Examen examen = examenRepository.findById(requestDTO.getLaboratoireExamenId())
                .orElseThrow(() -> new ExamenNotFoundException(
                        "Examen non trouvé: " + requestDTO.getLaboratoireExamenId()));

        // Vérifier que l'examen appartient bien au laboratoire
        if (!examen.getLaboratoire().getId().equals(requestDTO.getLaboratoireId())) {
            throw new PrelevementValidationException(
                    "L'examen ne correspond pas au laboratoire spécifié");
        }

        // Vérification unicité de l'ordre pour cet examen
        if (prelevementRepository.existsByLaboratoireExamenIdAndOrdrePrelevement(
                requestDTO.getLaboratoireExamenId(), requestDTO.getOrdrePrelevement())) {
            throw new PrelevementValidationException(
                    "Un prélèvement avec l'ordre " + requestDTO.getOrdrePrelevement() +
                            " existe déjà pour cet examen");
        }

        LaboratoirePrelevement entity = prelevementMapper.toEntity(requestDTO);
        LaboratoirePrelevement savedEntity = prelevementRepository.save(entity);

        log.info("Prélèvement créé avec succès - ID: {}", savedEntity.getId());
        return prelevementMapper.toResponseDTO(savedEntity);
    }

    /**
     * Récupère un prélèvement par son ID
     */
    @Transactional(readOnly = true)
    public PrelevementResponseDTO getPrelevementById(UUID id) {
        log.debug("Recherche du prélèvement avec l'ID: {}", id);

        LaboratoirePrelevement prelevement = prelevementRepository.findById(id)
                .orElseThrow(() -> new PrelevementNotFoundException("Prélèvement non trouvé: " + id));

        return prelevementMapper.toResponseDTO(prelevement);
    }

    /**
     * Met à jour un prélèvement existant
     */
    public PrelevementResponseDTO updatePrelevement(UUID id, PrelevementRequestDTO requestDTO) {
        log.info("Mise à jour du prélèvement: {}", id);

        LaboratoirePrelevement existingEntity = prelevementRepository.findById(id)
                .orElseThrow(() -> new PrelevementNotFoundException("Prélèvement non trouvé: " + id));

        // Vérification unicité de l'ordre si modifié
        if (requestDTO.getOrdrePrelevement() != null &&
                !requestDTO.getOrdrePrelevement().equals(existingEntity.getOrdrePrelevement())) {
            if (prelevementRepository.existsOrderForExamen(
                    existingEntity.getLaboratoireExamenId(),
                    requestDTO.getOrdrePrelevement(),
                    id)) {
                throw new PrelevementValidationException(
                        "Un prélèvement avec l'ordre " + requestDTO.getOrdrePrelevement() +
                                " existe déjà pour cet examen");
            }
        }

        prelevementMapper.updateEntity(requestDTO, existingEntity);
        LaboratoirePrelevement updatedEntity = prelevementRepository.save(existingEntity);

        log.info("Prélèvement mis à jour: {}", id);
        return prelevementMapper.toResponseDTO(updatedEntity);
    }

    /**
     * Supprime un prélèvement
     */
    public void deletePrelevement(UUID id) {
        log.info("Suppression du prélèvement: {}", id);

        LaboratoirePrelevement prelevement = prelevementRepository.findById(id)
                .orElseThrow(() -> new PrelevementNotFoundException("Prélèvement non trouvé: " + id));

        prelevementRepository.delete(prelevement);
        log.info("Prélèvement supprimé: {}", id);
    }

    // === RECHERCHES SPÉCIALISÉES ===

    /**
     * Récupère les prélèvements avec pagination et filtres
     */
    @Transactional(readOnly = true)
    public PagedResponseDTO<PrelevementResponseDTO> getPrelevements(
            int page, int size, String sortBy, String sortDirection,
            PrelevementSearchDTO searchDTO) {

        log.debug("Recherche des prélèvements - page: {}, size: {}", page, size);

        // Création du Pageable
        Sort.Direction direction = Sort.Direction.fromString(sortDirection);
        Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortBy));

        // Recherche avec filtres
        Page<LaboratoirePrelevement> prelevementPage = prelevementRepository.findWithFilters(
                searchDTO.getLaboratoireId(),
                searchDTO.getLaboratoireExamenId(),
                searchDTO.getNaturePrelevementCode(),
                searchDTO.getNomPrelevement(),
                searchDTO.getTypeTube(),
                searchDTO.getCouleurTube(),
                searchDTO.getPrelevementObligatoire(),
                pageable
        );

        // Conversion en DTOs
        List<PrelevementResponseDTO> content = prelevementMapper.toResponseDTOList(prelevementPage.getContent());

        return PagedResponseDTO.<PrelevementResponseDTO>builder()
                .content(content)
                .page(prelevementPage.getNumber())
                .size(prelevementPage.getSize())
                .totalElements(prelevementPage.getTotalElements())
                .totalPages(prelevementPage.getTotalPages())
                .first(prelevementPage.isFirst())
                .last(prelevementPage.isLast())
                .hasNext(prelevementPage.hasNext())
                .hasPrevious(prelevementPage.hasPrevious())
                .build();
    }

    /**
     * Récupère les prélèvements d'un laboratoire
     */
    @Transactional(readOnly = true)
    public List<PrelevementResponseDTO> getPrelevementsByLaboratoire(UUID laboratoireId) {
        log.debug("Recherche des prélèvements du laboratoire: {}", laboratoireId);

        List<LaboratoirePrelevement> prelevements = prelevementRepository
                .findByLaboratoireIdOrderByOrdrePrelevement(laboratoireId);

        return prelevementMapper.toResponseDTOList(prelevements);
    }

    /**
     * Récupère les prélèvements d'un examen
     */
    @Transactional(readOnly = true)
    public List<PrelevementResponseDTO> getPrelevementsByExamen(UUID laboratoireExamenId) {
        log.debug("Recherche des prélèvements de l'examen: {}", laboratoireExamenId);

        List<LaboratoirePrelevement> prelevements = prelevementRepository
                .findByLaboratoireExamenIdOrderByOrdrePrelevement(laboratoireExamenId);

        return prelevementMapper.toResponseDTOList(prelevements);
    }

    /**
     * Récupère les prélèvements par nature
     */
    @Transactional(readOnly = true)
    public List<PrelevementResponseDTO> getPrelevementsByNature(String naturePrelevementCode) {
        log.debug("Recherche des prélèvements de nature: {}", naturePrelevementCode);

        List<LaboratoirePrelevement> prelevements = prelevementRepository
                .findByNaturePrelevementCodeOrderByOrdrePrelevement(naturePrelevementCode);

        return prelevementMapper.toResponseDTOList(prelevements);
    }

    // === STATISTIQUES ===

    /**
     * Récupère les statistiques des prélèvements d'un laboratoire
     */
    @Transactional(readOnly = true)
    public Map<String, Object> getStatistiquesPrelevements(UUID laboratoireId) {
        log.debug("Calcul des statistiques de prélèvements pour laboratoire: {}", laboratoireId);

        // Statistiques générales
        long totalPrelevements = prelevementRepository.countByLaboratoireId(laboratoireId);

        // Statistiques par nature de prélèvement
        List<Object[]> statsParNature = prelevementRepository.getStatistiquesPrelevementsByLaboratoire(laboratoireId);

        // Répartition des tubes
        List<Object[]> repartitionTubes = prelevementRepository.getRepartitionTubes(laboratoireId);

        // Prélèvements les plus chers
        Pageable topPrix = PageRequest.of(0, 5);
        List<LaboratoirePrelevement> topPrixPrelevements = prelevementRepository.findTopByPrix(laboratoireId, topPrix);

        return Map.of(
                "totalPrelevements", totalPrelevements,
                "statistiquesParNature", statsParNature,
                "repartitionTubes", repartitionTubes,
                "prelevementsPrixEleves", prelevementMapper.toResponseDTOList(topPrixPrelevements)
        );
    }

    // === ACTIONS SPÉCIALES ===

    /**
     * Réorganise l'ordre des prélèvements d'un examen
     */
    public List<PrelevementResponseDTO> reorderPrelevements(UUID laboratoireExamenId, List<UUID> prelevementIds) {
        log.info("Réorganisation des prélèvements de l'examen: {}", laboratoireExamenId);

        if (prelevementIds == null || prelevementIds.isEmpty()) {
            throw new PrelevementValidationException("La liste des prélèvements ne peut pas être vide");
        }

        // Vérifier que tous les prélèvements appartiennent à l'examen
        List<LaboratoirePrelevement> prelevements = prelevementRepository.findAllById(prelevementIds);

        if (prelevements.size() != prelevementIds.size()) {
            throw new PrelevementNotFoundException("Certains prélèvements n'ont pas été trouvés");
        }

        for (LaboratoirePrelevement prelevement : prelevements) {
            if (!prelevement.getLaboratoireExamenId().equals(laboratoireExamenId)) {
                throw new PrelevementValidationException(
                        "Le prélèvement " + prelevement.getId() + " n'appartient pas à cet examen");
            }
        }

        // Mettre à jour l'ordre
        for (int i = 0; i < prelevementIds.size(); i++) {
            UUID prelevementId = prelevementIds.get(i);
            LaboratoirePrelevement prelevement = prelevements.stream()
                    .filter(p -> p.getId().equals(prelevementId))
                    .findFirst()
                    .orElseThrow();

            prelevement.setOrdrePrelevement(i + 1);
        }

        List<LaboratoirePrelevement> savedPrelevements = prelevementRepository.saveAll(prelevements);
        log.info("Ordre des prélèvements mis à jour pour l'examen: {}", laboratoireExamenId);

        return prelevementMapper.toResponseDTOList(savedPrelevements);
    }

    /**
     * Duplique les prélèvements d'un examen vers un autre examen
     */
    public List<PrelevementResponseDTO> duplicatePrelevements(UUID sourceExamenId, UUID targetExamenId) {
        log.info("Duplication des prélèvements de l'examen {} vers {}", sourceExamenId, targetExamenId);

        // Vérifier que l'examen cible existe
        Examen targetExamen = examenRepository.findById(targetExamenId)
                .orElseThrow(() -> new ExamenNotFoundException("Examen cible non trouvé: " + targetExamenId));

        // Récupérer les prélèvements source
        List<LaboratoirePrelevement> sourcePrelevements = prelevementRepository
                .findByLaboratoireExamenIdOrderByOrdrePrelevement(sourceExamenId);

        if (sourcePrelevements.isEmpty()) {
            throw new PrelevementValidationException("Aucun prélèvement à dupliquer trouvé pour l'examen source");
        }

        // Créer les nouveaux prélèvements
        List<LaboratoirePrelevement> newPrelevements = sourcePrelevements.stream()
                .map(source -> {
                    LaboratoirePrelevement newPrelevement = new LaboratoirePrelevement();
                    newPrelevement.setLaboratoireId(targetExamen.getLaboratoire().getId());
                    newPrelevement.setLaboratoireExamenId(targetExamenId);
                    newPrelevement.setNaturePrelevementCode(source.getNaturePrelevementCode());
                    newPrelevement.setNomPrelevementLabo(source.getNomPrelevementLabo());
                    newPrelevement.setTypeTubeLabo(source.getTypeTubeLabo());
                    newPrelevement.setCouleurTube(source.getCouleurTube());
                    newPrelevement.setVolumeRecommande(source.getVolumeRecommande());
                    newPrelevement.setInstructionsPrelevement(source.getInstructionsPrelevement());
                    newPrelevement.setPrixCoefficientPrelevement(source.getPrixCoefficientPrelevement());
                    newPrelevement.setPrixPrelevement(source.getPrixPrelevement());
                    newPrelevement.setPrelevementObligatoire(source.getPrelevementObligatoire());
                    newPrelevement.setOrdrePrelevement(source.getOrdrePrelevement());
                    return newPrelevement;
                })
                .toList();

        List<LaboratoirePrelevement> savedPrelevements = prelevementRepository.saveAll(newPrelevements);
        log.info("Duplication terminée: {} prélèvements créés", savedPrelevements.size());

        return prelevementMapper.toResponseDTOList(savedPrelevements);
    }

}