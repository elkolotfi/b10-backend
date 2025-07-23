package com.lims.referential.service;

import com.lims.referential.dto.request.CreateMedicamentRequest;
import com.lims.referential.dto.request.UpdateMedicamentRequest;
import com.lims.referential.dto.response.MedicamentResponse;
import com.lims.referential.entity.Medicament;
import com.lims.referential.mapper.MedicamentMapper;
import com.lims.referential.repository.MedicamentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Service pour la gestion des médicaments référentiels.
 * Utilise MedicamentMapper pour les conversions DTO/Entity.
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class MedicamentService {

    private final MedicamentRepository medicamentRepository;
    private final MedicamentMapper medicamentMapper; // <- Utilisation du mapper

    /**
     * Récupère tous les médicaments actifs avec mise en cache
     */
    @Transactional(readOnly = true)
    @Cacheable("medicaments")
    public List<MedicamentResponse> findAllActifs() {
        log.debug("Récupération de tous les médicaments actifs");

        List<Medicament> medicaments = medicamentRepository.findByActifTrue();
        return medicamentMapper.toResponseList(medicaments);
    }

    /**
     * Récupère les médicaments avec pagination
     */
    @Transactional(readOnly = true)
    public Page<MedicamentResponse> findAll(Pageable pageable) {
        log.debug("Récupération des médicaments avec pagination: {}", pageable);

        Page<Medicament> medicaments = medicamentRepository.findAll(pageable);
        return medicaments.map(medicamentMapper::toResponse);
    }

    /**
     * Récupère un médicament par son ID
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "medicament", key = "#id")
    public MedicamentResponse findById(UUID id) {
        log.debug("Récupération du médicament avec l'ID: {}", id);

        Medicament medicament = medicamentRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Médicament non trouvé avec l'ID: " + id));

        return medicamentMapper.toResponse(medicament);
    }

    /**
     * Récupère un médicament par son code CIS
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "medicament", key = "#codeCis")
    public MedicamentResponse findByCodeCis(String codeCis) {
        log.debug("Récupération du médicament avec le code CIS: {}", codeCis);

        Medicament medicament = medicamentRepository.findByCodeCis(codeCis)
                .orElseThrow(() -> new IllegalArgumentException("Médicament non trouvé avec le code CIS: " + codeCis));

        return medicamentMapper.toResponse(medicament);
    }

    /**
     * Recherche de médicaments par dénomination
     */
    @Transactional(readOnly = true)
    public List<MedicamentResponse> searchByDenomination(String denomination) {
        log.debug("Recherche de médicaments contenant: {}", denomination);

        List<Medicament> medicaments = medicamentRepository.findByDenominationContainingIgnoreCase(denomination);
        return medicamentMapper.toResponseList(medicaments);
    }

    /**
     * Crée un nouveau médicament
     */
    @CacheEvict(value = "medicaments", allEntries = true)
    public MedicamentResponse create(CreateMedicamentRequest request) {
        log.info("Création d'un nouveau médicament: {}", request.getCodeCis());

        // Vérifier que le code CIS n'existe pas déjà
        if (medicamentRepository.existsByCodeCis(request.getCodeCis())) {
            throw new IllegalArgumentException("Un médicament avec le code CIS " + request.getCodeCis() + " existe déjà");
        }

        // Conversion DTO -> Entity via le mapper
        Medicament medicament = medicamentMapper.toEntity(request);

        // Sauvegarde
        Medicament savedMedicament = medicamentRepository.save(medicament);

        log.info("Médicament créé avec succès: {} (ID: {})", savedMedicament.getCodeCis(), savedMedicament.getId());

        // Conversion Entity -> DTO via le mapper
        return medicamentMapper.toResponse(savedMedicament);
    }

    /**
     * Met à jour un médicament existant
     */
    @CacheEvict(value = {"medicaments", "medicament"}, allEntries = true)
    public MedicamentResponse update(UUID id, UpdateMedicamentRequest request) {
        log.info("Mise à jour du médicament avec l'ID: {}", id);

        // Récupération du médicament existant
        Medicament medicament = medicamentRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Médicament non trouvé avec l'ID: " + id));

        // Mise à jour via le mapper
        medicamentMapper.updateEntityFromRequest(request, medicament);

        // Sauvegarde
        Medicament updatedMedicament = medicamentRepository.save(medicament);

        log.info("Médicament mis à jour avec succès: {} (ID: {})", updatedMedicament.getCodeCis(), updatedMedicament.getId());

        // Conversion Entity -> DTO via le mapper
        return medicamentMapper.toResponse(updatedMedicament);
    }

    /**
     * Désactive un médicament (soft delete)
     */
    @CacheEvict(value = {"medicaments", "medicament"}, allEntries = true)
    public void desactiver(UUID id) {
        log.info("Désactivation du médicament avec l'ID: {}", id);

        Medicament medicament = medicamentRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Médicament non trouvé avec l'ID: " + id));

        medicament.desactiver();
        medicamentRepository.save(medicament);

        log.info("Médicament désactivé: {} (ID: {})", medicament.getCodeCis(), medicament.getId());
    }

    /**
     * Réactive un médicament
     */
    @CacheEvict(value = {"medicaments", "medicament"}, allEntries = true)
    public MedicamentResponse reactiver(UUID id) {
        log.info("Réactivation du médicament avec l'ID: {}", id);

        Medicament medicament = medicamentRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Médicament non trouvé avec l'ID: " + id));

        medicament.reactiver();
        Medicament reactivatedMedicament = medicamentRepository.save(medicament);

        log.info("Médicament réactivé: {} (ID: {})", reactivatedMedicament.getCodeCis(), reactivatedMedicament.getId());

        return medicamentMapper.toResponse(reactivatedMedicament);
    }

    /**
     * Supprime définitivement un médicament
     */
    @CacheEvict(value = {"medicaments", "medicament"}, allEntries = true)
    public void deleteDefinitivement(UUID id) {
        log.warn("Suppression définitive du médicament avec l'ID: {}", id);

        if (!medicamentRepository.existsById(id)) {
            throw new IllegalArgumentException("Médicament non trouvé avec l'ID: " + id);
        }

        medicamentRepository.deleteById(id);
        log.warn("Médicament supprimé définitivement (ID: {})", id);
    }

    /**
     * Récupère les médicaments remboursés
     */
    @Transactional(readOnly = true)
    @Cacheable("medicaments-rembourses")
    public List<MedicamentResponse> findMedicamentsRembourses() {
        log.debug("Récupération des médicaments remboursés");

        List<Medicament> medicaments = medicamentRepository.findByTauxRemboursementGreaterThan(0);
        return medicamentMapper.toResponseList(medicaments);
    }

    /**
     * Récupère les médicaments sous surveillance renforcée
     */
    @Transactional(readOnly = true)
    @Cacheable("medicaments-surveillance")
    public List<MedicamentResponse> findMedicamentsSurveillance() {
        log.debug("Récupération des médicaments sous surveillance renforcée");

        List<Medicament> medicaments = medicamentRepository.findBySurveillanceRenforceeTrue();
        return medicamentMapper.toResponseList(medicaments);
    }

    /**
     * Compte le nombre total de médicaments actifs
     */
    @Transactional(readOnly = true)
    public long countActifs() {
        return medicamentRepository.countByActifTrue();
    }

    /**
     * Vérifie si un médicament existe par son code CIS
     */
    @Transactional(readOnly = true)
    public boolean existsByCodeCis(String codeCis) {
        return medicamentRepository.existsByCodeCis(codeCis);
    }
}