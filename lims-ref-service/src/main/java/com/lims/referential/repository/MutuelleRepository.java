package com.lims.referential.repository;

import com.lims.referential.entity.Mutuelle;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface MutuelleRepository extends JpaRepository<Mutuelle, UUID> {

    /**
     * Recherche par code organisme
     */
    Optional<Mutuelle> findByCodeOrganismeAndActifTrue(String codeOrganisme);

    /**
     * Recherche par type d'organisme
     */
    Page<Mutuelle> findByTypeOrganismeAndActifTrue(String typeOrganisme, Pageable pageable);

    /**
     * Recherche par nom
     */
    Page<Mutuelle> findByNomContainingIgnoreCaseAndActifTrue(String nom, Pageable pageable);

    /**
     * Recherche textuelle
     */
    @Query("""
        SELECT m FROM Mutuelle m 
        WHERE m.actif = true 
        AND (UPPER(m.nom) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(m.nomCommercial) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(m.codeOrganisme) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(m.typeOrganisme) LIKE UPPER(CONCAT('%', :searchTerm, '%')))
        ORDER BY m.nom
        """)
    Page<Mutuelle> searchByTerm(@Param("searchTerm") String searchTerm, Pageable pageable);

    /**
     * Mutuelles avec tiers payant
     */
    @Query("""
        SELECT m FROM Mutuelle m 
        WHERE m.actif = true 
        AND JSON_EXTRACT(m.codesFacturation, '$.tiersPayant') = true
        """)
    List<Mutuelle> findWithTiersPayant();

    /**
     * Recherche par mode de transmission
     */
    @Query("""
        SELECT m FROM Mutuelle m 
        WHERE m.actif = true 
        AND m.modeTransmission = :modeTransmission
        """)
    Page<Mutuelle> findByModeTransmission(@Param("modeTransmission") String modeTransmission, Pageable pageable);

    /**
     * Mutuelles couvrant une analyse spécifique
     */
    @Query("""
        SELECT m FROM Mutuelle m 
        WHERE m.actif = true 
        AND (JSON_CONTAINS(JSON_EXTRACT(m.analysesCouvertes, '$[*].codeNabm'), JSON_QUOTE(:codeNabm))
             OR NOT JSON_CONTAINS(m.analysesExclues, JSON_QUOTE(:codeNabm)))
        """)
    List<Mutuelle> findCoveringAnalyse(@Param("codeNabm") String codeNabm);

    /**
     * Statistiques par type d'organisme
     */
    @Query("SELECT m.typeOrganisme, COUNT(m) FROM Mutuelle m WHERE m.actif = true GROUP BY m.typeOrganisme")
    List<Object[]> countByTypeOrganisme();

    /**
     * Mutuelles par région
     */
    @Query("SELECT m.region, COUNT(m) FROM Mutuelle m WHERE m.actif = true GROUP BY m.region")
    List<Object[]> countByRegion();

    /**
     * Mutuelles avec délai de paiement court
     */
    @Query("""
        SELECT m FROM Mutuelle m 
        WHERE m.actif = true 
        AND m.delaiPaiementJours <= :delaiMaximum
        ORDER BY m.delaiPaiementJours
        """)
    List<Mutuelle> findByDelaiPaiementMaximum(@Param("delaiMaximum") Integer delaiMaximum);
}