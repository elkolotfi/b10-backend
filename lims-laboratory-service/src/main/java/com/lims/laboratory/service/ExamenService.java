package com.lims.laboratory.service;

import com.lims.laboratory.dto.request.ExamenRequestDTO;
import com.lims.laboratory.dto.request.ExamenSearchDTO;
import com.lims.laboratory.dto.response.ExamenResponseDTO;
import com.lims.laboratory.dto.response.PagedResponseDTO;
import com.lims.laboratory.entity.Examen;
import com.lims.laboratory.entity.Laboratoire;
import com.lims.laboratory.exception.ExamenNotFoundException;
import com.lims.laboratory.exception.ExamenValidationException;
import com.lims.laboratory.exception.LaboratoireNotFoundException;
import com.lims.laboratory.mapper.ExamenMapper;
import com.lims.laboratory.repository.ExamenRepository;
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

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service pour la gestion des examens de laboratoire
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class ExamenService {

    private final ExamenRepository examenRepository;
    private final LaboratoireRepository laboratoireRepository;
    private final ExamenMapper examenMapper;

    // === Opérations CRUD ===

    /**
     * Crée un nouvel examen personnalisé pour un laboratoire
     */
    public ExamenResponseDTO createExamen(ExamenRequestDTO requestDTO) {
        log.info("Création d'un nouvel examen pour laboratoire: {}", requestDTO.getLaboratoireId());

        // Validation du laboratoire
        Laboratoire laboratoire = laboratoireRepository.findById(requestDTO.getLaboratoireId())
                .orElseThrow(() -> new LaboratoireNotFoundException(
                        "Laboratoire non trouvé: " + requestDTO.getLaboratoireId()));

        // Vérification unicité examen/laboratoire
        if (examenRepository.existsByLaboratoireIdAndExamenReferentielId(
                requestDTO.getLaboratoireId(), requestDTO.getExamenReferentielId())) {
            throw new ExamenValidationException(
                    "Cet examen existe déjà dans ce laboratoire");
        }

        // Création de l'entité
        Examen examen = examenMapper.toEntity(requestDTO);
        examen.setLaboratoire(laboratoire);
        examen.setCreatedAt(LocalDateTime.now());
        examen.setUpdatedAt(LocalDateTime.now());

        // Sauvegarde
        Examen savedExamen = examenRepository.save(examen);

        log.info("Examen créé avec succès - ID: {}, Laboratoire: {}",
                savedExamen.getId(), laboratoire.getNomCommercial());

        return examenMapper.toResponseDTO(savedExamen);
    }

    /**
     * Récupère les examens avec pagination et filtres
     */
    @Transactional(readOnly = true)
    public PagedResponseDTO<ExamenResponseDTO> getExamens(
            int page, int size, String sortBy, String sortDirection,
            UUID laboratoireId, ExamenSearchDTO searchDTO) {

        log.info("Recherche examens - page: {}, size: {}, laboratoireId: {}", page, size, laboratoireId);

        // Validation des paramètres de tri
        List<String> validSortFields = List.of("nomExamenLabo", "examenActif", "createdAt", "updatedAt");
        if (!validSortFields.contains(sortBy)) {
            sortBy = "nomExamenLabo";
        }

        Sort.Direction direction = "desc".equalsIgnoreCase(sortDirection) ?
                Sort.Direction.DESC : Sort.Direction.ASC;
        Sort sort = Sort.by(direction, sortBy);

        Pageable pageable = PageRequest.of(page, size, sort);
        Page<Examen> examensPage;

        // Application des filtres
        if (laboratoireId != null || hasSearchCriteria(searchDTO)) {
            examensPage = examenRepository.findWithFilters(
                    laboratoireId,
                    searchDTO.getNomExamen(),
                    searchDTO.getExamenActif(),
                    searchDTO.getExamenRealiseInternement(),
                    pageable
            );
        } else {
            examensPage = examenRepository.findAll(pageable);
        }

        // Conversion en DTO
        List<ExamenResponseDTO> examens = examensPage.getContent().stream()
                .map(examenMapper::toResponseDTO)
                .collect(Collectors.toList());

        return PagedResponseDTO.<ExamenResponseDTO>builder()
                .content(examens)
                .page(page)
                .size(size)
                .totalElements(examensPage.getTotalElements())
                .totalPages(examensPage.getTotalPages())
                .first(examensPage.isFirst())
                .last(examensPage.isLast())
                .build();
    }

    /**
     * Récupère un examen par son ID
     */
    @Transactional(readOnly = true)
    public ExamenResponseDTO getExamenById(UUID id) {
        log.info("Recherche examen par ID: {}", id);

        Examen examen = examenRepository.findById(id)
                .orElseThrow(() -> new ExamenNotFoundException("Examen non trouvé: " + id));

        return examenMapper.toResponseDTO(examen);
    }

    /**
     * Récupère un examen par son ID
     */
    @Transactional(readOnly = true)
    public ExamenResponseDTO getActifExamenById(UUID id) {
        log.info("Recherche examen par ID: {}", id);

        Examen examen = examenRepository.findByIdAndExamenActifTrue(id)
                .orElseThrow(() -> new ExamenNotFoundException("Examen non trouvé: " + id));

        return examenMapper.toResponseDTO(examen);
    }

    /**
     * Met à jour un examen existant
     */
    public ExamenResponseDTO updateExamen(UUID id, ExamenRequestDTO requestDTO) {
        log.info("Mise à jour examen ID: {}", id);

        // Récupération de l'examen existant
        Examen examen = examenRepository.findById(id)
                .orElseThrow(() -> new ExamenNotFoundException("Examen non trouvé: " + id));

        // Validation du laboratoire si changement
        if (!examen.getLaboratoire().getId().equals(requestDTO.getLaboratoireId())) {
            Laboratoire nouveauLaboratoire = laboratoireRepository.findById(requestDTO.getLaboratoireId())
                    .orElseThrow(() -> new LaboratoireNotFoundException(
                            "Laboratoire non trouvé: " + requestDTO.getLaboratoireId()));
            examen.setLaboratoire(nouveauLaboratoire);
        }

        // Vérification unicité si changement de référentiel
        if (!examen.getExamenReferentielId().equals(requestDTO.getExamenReferentielId())) {
            if (examenRepository.existsByLaboratoireIdAndExamenReferentielId(
                    requestDTO.getLaboratoireId(), requestDTO.getExamenReferentielId())) {
                throw new ExamenValidationException(
                        "Cet examen existe déjà dans ce laboratoire");
            }
        }

        // Mise à jour des champs
        examenMapper.updateEntity(requestDTO, examen);
        examen.setUpdatedAt(LocalDateTime.now());

        // Sauvegarde
        Examen updatedExamen = examenRepository.save(examen);

        log.info("Examen mis à jour avec succès - ID: {}", id);

        return examenMapper.toResponseDTO(updatedExamen);
    }

    /**
     * Supprime (désactive) un examen
     */
    public void deleteExamen(UUID id) {
        log.info("Suppression examen ID: {}", id);

        Examen examen = examenRepository.findById(id)
                .orElseThrow(() -> new ExamenNotFoundException("Examen non trouvé: " + id));

        // Soft delete - désactivation
        examen.setExamenActif(false);
        examen.setUpdatedAt(LocalDateTime.now());
        examenRepository.save(examen);

        log.info("Examen désactivé avec succès - ID: {}", id);
    }

    // === Recherches spécialisées ===

    /**
     * Récupère tous les examens actifs d'un laboratoire
     */
    @Transactional(readOnly = true)
    public List<ExamenResponseDTO> getExamensByLaboratoire(UUID laboratoireId) {
        log.info("Recherche examens actifs pour laboratoire: {}", laboratoireId);

        // Validation du laboratoire
        if (!laboratoireRepository.existsById(laboratoireId)) {
            throw new LaboratoireNotFoundException("Laboratoire non trouvé: " + laboratoireId);
        }

        List<Examen> examens = examenRepository.findByLaboratoireIdAndExamenActifTrueOrderByNomExamenLabo(laboratoireId);

        return examens.stream()
                .map(examenMapper::toResponseDTO)
                .collect(Collectors.toList());
    }

    /**
     * Trouve tous les laboratoires proposant un examen du référentiel
     */
    @Transactional(readOnly = true)
    public List<ExamenResponseDTO> getExamensByReferentiel(UUID examenReferentielId) {
        log.info("Recherche examens par référentiel: {}", examenReferentielId);

        List<Examen> examens = examenRepository.findByExamenReferentielIdAndExamenActifTrueOrderByNomExamenLabo(examenReferentielId);

        return examens.stream()
                .map(examenMapper::toResponseDTO)
                .collect(Collectors.toList());
    }

    // === Actions spécialisées ===

    /**
     * Active ou désactive un examen
     */
    public ExamenResponseDTO toggleActivation(UUID id, boolean actif) {
        log.info("Changement statut examen ID: {} -> {}", id, actif);

        Examen examen = examenRepository.findById(id)
                .orElseThrow(() -> new ExamenNotFoundException("Examen non trouvé: " + id));

        examen.setExamenActif(actif);
        examen.setUpdatedAt(LocalDateTime.now());

        Examen updatedExamen = examenRepository.save(examen);

        log.info("Statut examen modifié - ID: {}, Nouveau statut: {}", id, actif);

        return examenMapper.toResponseDTO(updatedExamen);
    }

    /**
     * Duplique un examen vers plusieurs laboratoires
     */
    public List<ExamenResponseDTO> dupliquerExamen(UUID sourceId, List<UUID> laboratoireIds) {
        log.info("Duplication examen ID: {} vers {} laboratoires", sourceId, laboratoireIds.size());

        // Récupération de l'examen source
        Examen examenSource = examenRepository.findById(sourceId)
                .orElseThrow(() -> new ExamenNotFoundException("Examen source non trouvé: " + sourceId));

        // Validation des laboratoires cibles
        List<Laboratoire> laboratoires = laboratoireRepository.findAllById(laboratoireIds);
        if (laboratoires.size() != laboratoireIds.size()) {
            throw new ExamenValidationException("Un ou plusieurs laboratoires cibles sont invalides");
        }

        List<Examen> nouveauxExamens = laboratoires.stream()
                .filter(lab -> !examenRepository.existsByLaboratoireIdAndExamenReferentielId(
                        lab.getId(), examenSource.getExamenReferentielId()))
                .map(laboratoire -> {
                    Examen nouvelExamen = new Examen();
                    // Copie des propriétés
                    nouvelExamen.setLaboratoire(laboratoire);
                    nouvelExamen.setExamenReferentielId(examenSource.getExamenReferentielId());
                    nouvelExamen.setNomExamenLabo(examenSource.getNomExamenLabo());
                    nouvelExamen.setExamenActif(examenSource.getExamenActif());
                    nouvelExamen.setExamenRealiseInternement(examenSource.getExamenRealiseInternement());
                    nouvelExamen.setDelaiRenduHabituel(examenSource.getDelaiRenduHabituel());
                    nouvelExamen.setDelaiRenduUrgent(examenSource.getDelaiRenduUrgent());
                    nouvelExamen.setConditionsParticulieres(examenSource.getConditionsParticulieres());
                    nouvelExamen.setCreatedAt(LocalDateTime.now());
                    nouvelExamen.setUpdatedAt(LocalDateTime.now());
                    return nouvelExamen;
                })
                .collect(Collectors.toList());

        // Sauvegarde des nouveaux examens
        List<Examen> examensCreés = examenRepository.saveAll(nouveauxExamens);

        log.info("Duplication terminée - {} nouveaux examens créés", examensCreés.size());

        return examensCreés.stream()
                .map(examenMapper::toResponseDTO)
                .collect(Collectors.toList());
    }

    // === Statistiques ===

    /**
     * Génère des statistiques sur les examens
     */
    @Transactional(readOnly = true)
    public Map<String, Object> getStatistiques(UUID laboratoireId) {
        log.info("Génération statistiques examens - laboratoireId: {}", laboratoireId);

        Map<String, Object> stats = new HashMap<>();

        if (laboratoireId != null) {
            // Statistiques pour un laboratoire spécifique
            long totalExamens = examenRepository.countByLaboratoireId(laboratoireId);
            long examensActifs = examenRepository.countByLaboratoireIdAndExamenActif(laboratoireId, true);
            long examensInactifs = totalExamens - examensActifs;
            long examensInternes = examenRepository.countByLaboratoireIdAndExamenRealiseInternement(laboratoireId, true);

            stats.put("laboratoireId", laboratoireId);
            stats.put("totalExamens", totalExamens);
            stats.put("examensActifs", examensActifs);
            stats.put("examensInactifs", examensInactifs);
            stats.put("examensRéalisésInternement", examensInternes);
            stats.put("pourcentageActifs", totalExamens > 0 ? (examensActifs * 100.0 / totalExamens) : 0);
        } else {
            // Statistiques globales
            long totalExamens = examenRepository.count();
            long examensActifs = examenRepository.countByExamenActif(true);
            long examensInactifs = totalExamens - examensActifs;

            List<Object[]> statsByLaboratoire = examenRepository.getStatistiquesByLaboratoire();

            stats.put("totalExamens", totalExamens);
            stats.put("examensActifs", examensActifs);
            stats.put("examensInactifs", examensInactifs);
            stats.put("nombreLaboratoires", statsByLaboratoire.size());
            stats.put("statistiquesParLaboratoire", statsByLaboratoire);
        }

        return stats;
    }

    // === Méthodes utilitaires ===

    private boolean hasSearchCriteria(ExamenSearchDTO searchDTO) {
        return searchDTO != null && (
                StringUtils.hasText(searchDTO.getNomExamen()) ||
                        searchDTO.getExamenActif() != null ||
                        searchDTO.getExamenRealiseInternement() != null
        );
    }
}