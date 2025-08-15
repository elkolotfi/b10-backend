package com.lims.laboratory.repository;

import com.lims.laboratory.entity.LaboratoirePrelevement;
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
 * Repository pour la gestion des prélèvements de laboratoire
 */
@Repository
public interface PrelevementRepository extends JpaRepository<LaboratoirePrelevement, UUID> {

    // === REQUÊTES DE BASE ===

    /**
     * Vérifie si un prélèvement existe déjà pour un examen et un ordre donnés
     */
    boolean existsByLaboratoireExamenIdAndOrdrePrelevement(UUID laboratoireExamenId, Integer ordrePrelevement);

    /**
     * Trouve les prélèvements d'un laboratoire triés par ordre
     */
    List<LaboratoirePrelevement> findByLaboratoireIdOrderByOrdrePrelevement(UUID laboratoireId);

    /**
     * Trouve les prélèvements d'un examen triés par ordre
     */
    List<LaboratoirePrelevement> findByLaboratoireExamenIdOrderByOrdrePrelevement(UUID laboratoireExamenId);

    /**
     * Trouve les prélèvements par nature de prélèvement
     */
    List<LaboratoirePrelevement> findByNaturePrelevementCodeOrderByOrdrePrelevement(String naturePrelevementCode);

    /**
     * Trouve un prélèvement spécifique par laboratoire, examen et ordre
     */
    Optional<LaboratoirePrelevement> findByLaboratoireIdAndLaboratoireExamenIdAndOrdrePrelevement(
            UUID laboratoireId, UUID laboratoireExamenId, Integer ordrePrelevement);

    // === REQUÊTES DE COMPTAGE ===

    /**
     * Compte les prélèvements par laboratoire
     */
    long countByLaboratoireId(UUID laboratoireId);

    /**
     * Compte les prélèvements par examen
     */
    long countByLaboratoireExamenId(UUID laboratoireExamenId);

    /**
     * Compte les prélèvements obligatoires par examen
     */
    long countByLaboratoireExamenIdAndPrelevementObligatoire(UUID laboratoireExamenId, Boolean obligatoire);

    /**
     * Compte les prélèvements par nature
     */
    long countByNaturePrelevementCode(String naturePrelevementCode);

    // === REQUÊTES AVEC FILTRES ===

    /**
     * Recherche avec filtres multiples
     */
    @Query("""
        SELECT p FROM LaboratoirePrelevement p
        LEFT JOIN p.laboratoire l
        LEFT JOIN p.laboratoireExamen e
        WHERE (:laboratoireId IS NULL OR p.laboratoireId = :laboratoireId)
        AND (:laboratoireExamenId IS NULL OR p.laboratoireExamenId = :laboratoireExamenId)
        AND (:naturePrelevementCode IS NULL OR p.naturePrelevementCode = :naturePrelevementCode)
        AND (:nomPrelevement IS NULL OR LOWER(p.nomPrelevementLabo) LIKE LOWER(CONCAT('%', :nomPrelevement, '%')))
        AND (:typeTube IS NULL OR LOWER(p.typeTubeLabo) LIKE LOWER(CONCAT('%', :typeTube, '%')))
        AND (:couleurTube IS NULL OR LOWER(p.couleurTube) LIKE LOWER(CONCAT('%', :couleurTube, '%')))
        AND (:prelevementObligatoire IS NULL OR p.prelevementObligatoire = :prelevementObligatoire)
        ORDER BY p.laboratoire.nomCommercial, p.laboratoireExamen.nomExamenLabo, p.ordrePrelevement
    """)
    Page<LaboratoirePrelevement> findWithFilters(
            @Param("laboratoireId") UUID laboratoireId,
            @Param("laboratoireExamenId") UUID laboratoireExamenId,
            @Param("naturePrelevementCode") String naturePrelevementCode,
            @Param("nomPrelevement") String nomPrelevement,
            @Param("typeTube") String typeTube,
            @Param("couleurTube") String couleurTube,
            @Param("prelevementObligatoire") Boolean prelevementObligatoire,
            Pageable pageable
    );

    /**
     * Recherche par laboratoire avec filtres
     */
    @Query("""
        SELECT p FROM LaboratoirePrelevement p
        LEFT JOIN p.laboratoireExamen e
        WHERE p.laboratoireId = :laboratoireId
        AND (:laboratoireExamenId IS NULL OR p.laboratoireExamenId = :laboratoireExamenId)
        AND (:naturePrelevementCode IS NULL OR p.naturePrelevementCode = :naturePrelevementCode)
        AND (:nomPrelevement IS NULL OR LOWER(p.nomPrelevementLabo) LIKE LOWER(CONCAT('%', :nomPrelevement, '%')))
        AND (:typeTube IS NULL OR LOWER(p.typeTubeLabo) LIKE LOWER(CONCAT('%', :typeTube, '%')))
        AND (:couleurTube IS NULL OR LOWER(p.couleurTube) LIKE LOWER(CONCAT('%', :couleurTube, '%')))
        AND (:prelevementObligatoire IS NULL OR p.prelevementObligatoire = :prelevementObligatoire)
        ORDER BY p.laboratoireExamen.nomExamenLabo, p.ordrePrelevement
    """)
    Page<LaboratoirePrelevement> findByLaboratoireWithFilters(
            @Param("laboratoireId") UUID laboratoireId,
            @Param("laboratoireExamenId") UUID laboratoireExamenId,
            @Param("naturePrelevementCode") String naturePrelevementCode,
            @Param("nomPrelevement") String nomPrelevement,
            @Param("typeTube") String typeTube,
            @Param("couleurTube") String couleurTube,
            @Param("prelevementObligatoire") Boolean prelevementObligatoire,
            Pageable pageable
    );

    // === REQUÊTES DE STATISTIQUES ===

    /**
     * Statistiques des prélèvements par laboratoire
     */
    @Query("""
        SELECT 
            p.naturePrelevementCode as natureCode,
            COUNT(p) as nombrePrelevements,
            COUNT(CASE WHEN p.prelevementObligatoire = true THEN 1 END) as nombreObligatoires,
            AVG(p.prixPrelevement) as prixMoyen
        FROM LaboratoirePrelevement p
        WHERE p.laboratoireId = :laboratoireId
        GROUP BY p.naturePrelevementCode
        ORDER BY nombrePrelevements DESC
    """)
    List<Object[]> getStatistiquesPrelevementsByLaboratoire(@Param("laboratoireId") UUID laboratoireId);

    /**
     * Répartition des types de tubes par laboratoire
     */
    @Query("""
        SELECT 
            p.typeTubeLabo as typeTube,
            p.couleurTube as couleurTube,
            COUNT(p) as nombre
        FROM LaboratoirePrelevement p
        WHERE p.laboratoireId = :laboratoireId
        AND p.typeTubeLabo IS NOT NULL
        GROUP BY p.typeTubeLabo, p.couleurTube
        ORDER BY nombre DESC
    """)
    List<Object[]> getRepartitionTubes(@Param("laboratoireId") UUID laboratoireId);

    /**
     * Prélèvements avec prix les plus élevés
     */
    @Query("""
        SELECT p FROM LaboratoirePrelevement p
        WHERE p.laboratoireId = :laboratoireId
        AND p.prixPrelevement IS NOT NULL
        ORDER BY p.prixPrelevement DESC
    """)
    List<LaboratoirePrelevement> findTopByPrix(@Param("laboratoireId") UUID laboratoireId, Pageable pageable);

    // === VALIDATION D'UNICITÉ ===

    /**
     * Vérifie l'unicité de l'ordre pour un examen (utile pour la validation avant mise à jour)
     */
    @Query("""
        SELECT COUNT(p) > 0 FROM LaboratoirePrelevement p
        WHERE p.laboratoireExamenId = :laboratoireExamenId
        AND p.ordrePrelevement = :ordre
        AND (:excludeId IS NULL OR p.id != :excludeId)
    """)
    boolean existsOrderForExamen(
            @Param("laboratoireExamenId") UUID laboratoireExamenId,
            @Param("ordre") Integer ordre,
            @Param("excludeId") UUID excludeId
    );
}