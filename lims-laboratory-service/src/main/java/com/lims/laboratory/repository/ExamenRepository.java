package com.lims.laboratory.repository;

import com.lims.laboratory.entity.Examen;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository pour la gestion des examens de laboratoire
 */
@Repository
public interface ExamenRepository extends JpaRepository<Examen, UUID> {

    // === Requêtes de base ===

    /**
     * Vérifie si un examen existe déjà pour un laboratoire et un référentiel donné
     */
    boolean existsByLaboratoireIdAndExamenReferentielId(UUID laboratoireId, UUID examenReferentielId);

    /**
     * Trouve les examens actifs d'un laboratoire triés par nom
     */
    List<Examen> findByLaboratoireIdAndExamenActifTrueOrderByNomExamenLabo(UUID laboratoireId);

    /**
     * Trouve les examens par référentiel triés par nom
     */
    List<Examen> findByExamenReferentielIdAndExamenActifTrueOrderByNomExamenLabo(UUID examenReferentielId);


    Optional<Examen> findByIdAndExamenActifTrue(UUID examenId);

    // === Requêtes de comptage ===

    /**
     * Compte les examens par laboratoire
     */
    long countByLaboratoireId(UUID laboratoireId);

    /**
     * Compte les examens actifs/inactifs par laboratoire
     */
    long countByLaboratoireIdAndExamenActif(UUID laboratoireId, Boolean examenActif);

    /**
     * Compte les examens réalisés en interne par laboratoire
     */
    long countByLaboratoireIdAndExamenRealiseInternement(UUID laboratoireId, Boolean realiseInternement);

    /**
     * Compte les examens actifs globalement
     */
    long countByExamenActif(Boolean examenActif);

    // === Requêtes avec filtres ===

    /**
     * Recherche avec filtres multiples
     */
    @Query("""
        SELECT e FROM Examen e
        WHERE (:laboratoireId IS NULL OR e.laboratoire.id = :laboratoireId)
        AND (:nomExamen IS NULL OR e.nomExamenLabo LIKE :nomExamen)
        AND (:examenActif IS NULL OR e.examenActif = :examenActif)
        AND (:realiseInternement IS NULL OR e.examenRealiseInternement = :realiseInternement)
        ORDER BY e.nomExamenLabo
    """)
    Page<Examen> findWithFilters(
            @Param("laboratoireId") UUID laboratoireId,
            @Param("nomExamen") String nomExamen,
            @Param("examenActif") Boolean examenActif,
            @Param("realiseInternement") Boolean realiseInternement,
            Pageable pageable
    );

    // === Statistiques ===

    /**
     * Statistiques par laboratoire
     */
    @Query("""
        SELECT l.nomCommercial, COUNT(e), 
               SUM(CASE WHEN e.examenActif = true THEN 1 ELSE 0 END),
               SUM(CASE WHEN e.examenRealiseInternement = true THEN 1 ELSE 0 END)
        FROM Examen e 
        JOIN e.laboratoire l 
        GROUP BY l.id, l.nomCommercial
        ORDER BY COUNT(e) DESC
        """)
    List<Object[]> getStatistiquesByLaboratoire();

    // === Requêtes spécialisées ===

    /**
     * Trouve les examens sans délai de rendu configuré
     */
    @Query("""
        SELECT e FROM Examen e 
        WHERE e.examenActif = true 
        AND (e.delaiRenduHabituel IS NULL OR e.delaiRenduHabituel = '')
        ORDER BY e.nomExamenLabo
        """)
    List<Examen> findExamensSansDelai();

    /**
     * Trouve les examens sous-traités
     */
    @Query("""
        SELECT DISTINCT e FROM Examen e 
        JOIN e.analyses a 
        WHERE a.sousTraite = true 
        AND e.examenActif = true
        ORDER BY e.nomExamenLabo
        """)
    List<Examen> findExamensSousTraites();

    /**
     * Recherche textuelle avancée sur nom et conditions
     */
    @Query("""
        SELECT e FROM Examen e 
        WHERE e.examenActif = true
        AND (
            LOWER(e.nomExamenLabo) LIKE LOWER(CONCAT('%', :searchTerm, '%'))
            OR LOWER(e.conditionsParticulieres) LIKE LOWER(CONCAT('%', :searchTerm, '%'))
        )
        ORDER BY e.nomExamenLabo
        """)
    List<Examen> searchByText(@Param("searchTerm") String searchTerm);
}