package com.lims.referential.repository;

import com.lims.referential.entity.Geographique;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface GeographiqueRepository extends JpaRepository<Geographique, UUID> {

    /**
     * Recherche par code postal
     */
    List<Geographique> findByCodePostalAndActifTrue(String codePostal);

    /**
     * Recherche par nom de commune
     */
    List<Geographique> findByNomCommuneContainingIgnoreCaseAndActifTrue(String nomCommune);

    /**
     * Recherche par département
     */
    List<Geographique> findByDepartementAndActifTrue(String departement);

    /**
     * Recherche par code département
     */
    List<Geographique> findByCodeDepartementAndActifTrue(String codeDepartement);

    /**
     * Recherche par région
     */
    List<Geographique> findByRegionAndActifTrue(String region);

    /**
     * Recherche par code région
     */
    List<Geographique> findByCodeRegionAndActifTrue(String codeRegion);

    /**
     * Recherche textuelle dans les communes
     */
    @Query("""
        SELECT g FROM Geographique g 
        WHERE g.actif = true 
        AND (UPPER(g.nomCommune) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR g.codePostal LIKE CONCAT(:searchTerm, '%')
             OR UPPER(g.departement) LIKE UPPER(CONCAT('%', :searchTerm, '%')))
        ORDER BY g.nomCommune
        """)
    Page<Geographique> searchByTerm(@Param("searchTerm") String searchTerm, Pageable pageable);

    /**
     * Communes dans une zone de desserte d'un laboratoire
     */
    @Query("""
        SELECT g FROM Geographique g 
        WHERE g.actif = true 
        AND JSON_CONTAINS(g.laboratoiresZone, JSON_QUOTE(:laboratoireId))
        """)
    List<Geographique> findZonesDesserteByLaboratoire(@Param("laboratoireId") UUID laboratoireId);

    /**
     * Communes avec coordonnées GPS
     */
    @Query("""
        SELECT g FROM Geographique g 
        WHERE g.actif = true 
        AND g.latitude IS NOT NULL 
        AND g.longitude IS NOT NULL
        """)
    List<Geographique> findWithCoordinates();

    /**
     * Compter les départements distincts
     */
    @Query("SELECT COUNT(DISTINCT g.departement) FROM Geographique g WHERE g.actif = true")
    long countDistinctDepartements();

    /**
     * Compter les régions distinctes
     */
    @Query("SELECT COUNT(DISTINCT g.region) FROM Geographique g WHERE g.actif = true")
    long countDistinctRegions();

    /**
     * Statistiques par département
     */
    @Query("SELECT g.departement, COUNT(g) FROM Geographique g WHERE g.actif = true GROUP BY g.departement ORDER BY COUNT(g) DESC")
    List<Object[]> countByDepartement();

    /**
     * Statistiques par région
     */
    @Query("SELECT g.region, COUNT(g) FROM Geographique g WHERE g.actif = true GROUP BY g.region ORDER BY COUNT(g) DESC")
    List<Object[]> countByRegion();

    /**
     * Communes les plus peuplées
     */
    @Query("""
        SELECT g FROM Geographique g 
        WHERE g.actif = true 
        AND g.population IS NOT NULL 
        ORDER BY g.population DESC
        """)
    List<Geographique> findTopByPopulation(Pageable pageable);

    /**
     * Recherche par code INSEE
     */
    List<Geographique> findByCodeCommuneAndActifTrue(String codeCommune);
}