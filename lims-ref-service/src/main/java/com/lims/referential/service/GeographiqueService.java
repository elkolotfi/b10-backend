package com.lims.referential.service;

import com.lims.referential.entity.Geographique;
import com.lims.referential.repository.GeographiqueRepository;
import com.lims.referential.dto.request.GeographiqueRequestDTO;
import com.lims.referential.dto.response.GeographiqueResponseDTO;
import com.lims.referential.dto.common.PagedResponseDTO;
import com.lims.referential.exception.ResourceNotFoundException;
import com.lims.referential.mapper.GeographiqueMapper;
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
public class GeographiqueService {

    private final GeographiqueRepository geographiqueRepository;
    private final GeographiqueMapper geographiqueMapper;

    @Cacheable(value = "geographique", key = "'all-' + #pageable.pageNumber + '-' + #pageable.pageSize")
    public PagedResponseDTO<GeographiqueResponseDTO> findAll(Pageable pageable) {
        log.debug("Récupération de toutes les données géographiques - page: {}, size: {}", pageable.getPageNumber(), pageable.getPageSize());

        Page<Geographique> geographiquePage = geographiqueRepository.findAll(pageable);
        List<GeographiqueResponseDTO> geographiquesDTOs = geographiquePage.getContent()
                .stream()
                .map(geographiqueMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<GeographiqueResponseDTO>builder()
                .content(geographiquesDTOs)
                .page(geographiquePage.getNumber())
                .size(geographiquePage.getSize())
                .totalElements(geographiquePage.getTotalElements())
                .totalPages(geographiquePage.getTotalPages())
                .first(geographiquePage.isFirst())
                .last(geographiquePage.isLast())
                .empty(geographiquePage.isEmpty())
                .build();
    }

    @Cacheable(value = "geographique", key = "#id")
    public GeographiqueResponseDTO findById(UUID id) {
        log.debug("Recherche des données géographiques avec l'ID: {}", id);

        Geographique geographique = geographiqueRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Données géographiques non trouvées avec l'ID: " + id));

        return geographiqueMapper.toResponseDTO(geographique);
    }

    @Cacheable(value = "geographique", key = "'cp-' + #codePostal")
    public List<GeographiqueResponseDTO> findByCodePostal(String codePostal) {
        log.debug("Recherche par code postal: {}", codePostal);

        List<Geographique> communes = geographiqueRepository.findByCodePostalAndActifTrue(codePostal);

        return communes.stream()
                .map(geographiqueMapper::toResponseDTO)
                .toList();
    }

    @Cacheable(value = "geographique", key = "'ville-' + #ville")
    public List<GeographiqueResponseDTO> findByVille(String ville) {
        log.debug("Recherche par ville: {}", ville);

        List<Geographique> communes = geographiqueRepository.findByNomCommuneContainingIgnoreCaseAndActifTrue(ville);

        return communes.stream()
                .map(geographiqueMapper::toResponseDTO)
                .toList();
    }

    @Cacheable(value = "geographique", key = "'dept-' + #departement")
    public List<GeographiqueResponseDTO> findByDepartement(String departement) {
        log.debug("Recherche par département: {}", departement);

        List<Geographique> communes = geographiqueRepository.findByDepartementAndActifTrue(departement);

        return communes.stream()
                .map(geographiqueMapper::toResponseDTO)
                .toList();
    }

    @Cacheable(value = "geographique", key = "'distance-' + #lat1 + '-' + #lon1 + '-' + #lat2 + '-' + #lon2")
    public Map<String, Object> calculateDistance(BigDecimal lat1, BigDecimal lon1, BigDecimal lat2, BigDecimal lon2) {
        log.debug("Calcul de distance entre ({}, {}) et ({}, {})", lat1, lon1, lat2, lon2);

        double distance = calculateHaversineDistance(lat1.doubleValue(), lon1.doubleValue(), lat2.doubleValue(), lon2.doubleValue());

        return Map.of(
                "distance_km", Math.round(distance * 100.0) / 100.0,
                "point1", Map.of("latitude", lat1, "longitude", lon1),
                "point2", Map.of("latitude", lat2, "longitude", lon2)
        );
    }

    public List<GeographiqueResponseDTO> findZonesDesserteByLaboratoire(UUID laboratoireId) {
        log.debug("Recherche des zones de desserte pour le laboratoire: {}", laboratoireId);

        List<Geographique> zones = geographiqueRepository.findZonesDesserteByLaboratoire(laboratoireId);

        return zones.stream()
                .map(geographiqueMapper::toResponseDTO)
                .toList();
    }

    public Map<String, Object> optimiserTournee(Map<String, Object> parametres) {
        log.debug("Optimisation de tournée avec paramètres: {}", parametres);

        // TODO: Implémenter l'algorithme d'optimisation de tournée
        // Pour l'instant, retourner une réponse basique

        return Map.of(
                "message", "Optimisation de tournée non encore implémentée",
                "parametres", parametres
        );
    }

    @Transactional
    @CacheEvict(value = "geographique", allEntries = true)
    public GeographiqueResponseDTO create(GeographiqueRequestDTO requestDTO) {
        log.info("Création de nouvelles données géographiques: {} - {}", requestDTO.getCodePostal(), requestDTO.getNomCommune());

        Geographique geographique = geographiqueMapper.toEntity(requestDTO);
        Geographique savedGeographique = geographiqueRepository.save(geographique);

        log.info("Données géographiques créées avec succès - ID: {}", savedGeographique.getId());
        return geographiqueMapper.toResponseDTO(savedGeographique);
    }

    @Transactional
    @CacheEvict(value = "geographique", allEntries = true)
    public GeographiqueResponseDTO update(UUID id, GeographiqueRequestDTO requestDTO) {
        log.info("Mise à jour des données géographiques avec l'ID: {}", id);

        Geographique existingGeographique = geographiqueRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Données géographiques non trouvées avec l'ID: " + id));

        geographiqueMapper.updateEntityFromDTO(requestDTO, existingGeographique);
        Geographique updatedGeographique = geographiqueRepository.save(existingGeographique);

        log.info("Données géographiques mises à jour avec succès - ID: {}", updatedGeographique.getId());
        return geographiqueMapper.toResponseDTO(updatedGeographique);
    }

    @Transactional
    @CacheEvict(value = "geographique", allEntries = true)
    public void delete(UUID id) {
        log.info("Suppression des données géographiques avec l'ID: {}", id);

        Geographique geographique = geographiqueRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Données géographiques non trouvées avec l'ID: " + id));

        geographique.markAsDeleted();
        geographiqueRepository.save(geographique);

        log.info("Données géographiques supprimées avec succès - ID: {}", id);
    }

    @Cacheable(value = "geographique", key = "'stats'")
    public Map<String, Object> getStatistics() {
        log.debug("Récupération des statistiques géographiques");

        long totalCommunes = geographiqueRepository.count();
        long totalDepartements = geographiqueRepository.countDistinctDepartements();
        long totalRegions = geographiqueRepository.countDistinctRegions();

        return Map.of(
                "totalCommunes", totalCommunes,
                "totalDepartements", totalDepartements,
                "totalRegions", totalRegions
        );
    }

    // Méthode utilitaire pour le calcul de distance Haversine
    private double calculateHaversineDistance(double lat1, double lon1, double lat2, double lon2) {
        final int R = 6371; // Rayon de la Terre en kilomètres

        double latDistance = Math.toRadians(lat2 - lat1);
        double lonDistance = Math.toRadians(lon2 - lon1);

        double a = Math.sin(latDistance / 2) * Math.sin(latDistance / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(lonDistance / 2) * Math.sin(lonDistance / 2);

        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

        return R * c;
    }
}