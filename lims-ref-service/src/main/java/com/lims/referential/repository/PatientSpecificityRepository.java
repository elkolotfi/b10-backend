package com.lims.referential.repository;

import com.lims.referential.entity.PatientSpecificity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface PatientSpecificityRepository extends JpaRepository<PatientSpecificity, UUID> {

    /**
     * Recherche par catégorie
     */
    Page<PatientSpecificity> findByCategoryIdAndActifTrue(String categoryId, Pageable pageable);

    /**
     * Recherche par niveau d'alerte
     */
    Page<PatientSpecificity> findByNiveauAlerteAndActifTrue(String niveauAlerte, Pageable pageable);

    /**
     * Recherche textuelle avec mots-clés (VERSION CORRIGÉE POSTGRESQL)
     */
    @Query(value = """
        SELECT * FROM lims_referential.patient_specificities ps 
        WHERE ps.actif = true 
        AND ps.deleted_at IS NULL
        AND (
            UPPER(ps.titre) LIKE UPPER('%' || ?1 || '%')
            OR UPPER(ps.description) LIKE UPPER('%' || ?1 || '%')
            OR EXISTS (
                SELECT 1 FROM jsonb_array_elements_text(ps.mots_cles) AS mot
                WHERE UPPER(mot) LIKE UPPER('%' || ?1 || '%')
            )
        )
        ORDER BY ps.priorite_preleveur DESC, ps.titre
        """, nativeQuery = true)
    List<PatientSpecificity> searchByTerm(String searchTerm);

    /**
     * Version pageable pour la recherche textuelle
     */
    @Query(value = """
        SELECT * FROM lims_referential.patient_specificities ps 
        WHERE ps.actif = true 
        AND ps.deleted_at IS NULL
        AND (
            UPPER(ps.titre) LIKE UPPER('%' || ?1 || '%')
            OR UPPER(ps.description) LIKE UPPER('%' || ?1 || '%')
            OR EXISTS (
                SELECT 1 FROM jsonb_array_elements_text(ps.mots_cles) AS mot
                WHERE UPPER(mot) LIKE UPPER('%' || ?1 || '%')
            )
        )
        ORDER BY ps.priorite_preleveur DESC, ps.titre
        """,
            countQuery = """
        SELECT COUNT(*) FROM lims_referential.patient_specificities ps 
        WHERE ps.actif = true 
        AND ps.deleted_at IS NULL
        AND (
            UPPER(ps.titre) LIKE UPPER('%' || ?1 || '%')
            OR UPPER(ps.description) LIKE UPPER('%' || ?1 || '%')
            OR EXISTS (
                SELECT 1 FROM jsonb_array_elements_text(ps.mots_cles) AS mot
                WHERE UPPER(mot) LIKE UPPER('%' || ?1 || '%')
            )
        )
        """,
            nativeQuery = true)
    Page<PatientSpecificity> searchByTermPageable(String searchTerm, Pageable pageable);

    /**
     * Filtrage multi-critères (VERSION JPQL - PAS DE PROBLÈME)
     */
    @Query("""
        SELECT ps FROM PatientSpecificity ps 
        WHERE ps.actif = true
        AND (:categoryId IS NULL OR ps.categoryId = :categoryId)
        AND (:niveauAlerte IS NULL OR ps.niveauAlerte = :niveauAlerte)
        AND (:actif IS NULL OR ps.actif = :actif)
        """)
    Page<PatientSpecificity> findWithFilters(
            @Param("categoryId") String categoryId,
            @Param("niveauAlerte") String niveauAlerte,
            @Param("actif") Boolean actif,
            Pageable pageable);

    /**
     * Spécificités affectant une analyse donnée (VERSION CORRIGÉE - Sans conflit ?)
     */
    @Query(value = """
        SELECT * FROM lims_referential.patient_specificities ps 
        WHERE ps.actif = true 
        AND ps.deleted_at IS NULL
        AND (
            jsonb_exists(ps.analyses_contre_indiquees, ?1)
            OR jsonb_exists(ps.analyses_modifiees, ?1)
        )
        """, nativeQuery = true)
    List<PatientSpecificity> findAffectingAnalyse(String codeNabm);

    /**
     * Spécificités par priorité préleveur
     */
    Page<PatientSpecificity> findByPrioritePreleveurAndActifTrueOrderByTitre(Integer prioritePreleveur, Pageable pageable);

    /**
     * Spécificités nécessitant du temps supplémentaire
     */
    @Query("""
        SELECT ps FROM PatientSpecificity ps 
        WHERE ps.actif = true 
        AND ps.tempsSupplementaireMinutes > 0
        ORDER BY ps.tempsSupplementaireMinutes DESC
        """)
    List<PatientSpecificity> findRequiringExtraTime();

    /**
     * Statistiques par niveau d'alerte
     */
    @Query("SELECT ps.niveauAlerte, COUNT(ps) FROM PatientSpecificity ps WHERE ps.actif = true GROUP BY ps.niveauAlerte")
    List<Object[]> getSpecificitiesByNiveauAlerte();

    /**
     * Statistiques par catégorie
     */
    @Query("SELECT ps.categoryId, COUNT(ps) FROM PatientSpecificity ps WHERE ps.actif = true GROUP BY ps.categoryId")
    List<Object[]> getSpecificitiesByCategory();

    /**
     * Recherche par mot-clé spécifique (VERSION CORRIGÉE - Sans conflit ?)
     */
    @Query(value = """
        SELECT * FROM lims_referential.patient_specificities ps 
        WHERE ps.actif = true 
        AND ps.deleted_at IS NULL
        AND jsonb_exists(ps.mots_cles, ?1)
        """, nativeQuery = true)
    List<PatientSpecificity> findByMotCle(String motCle);

    /**
     * Spécificités critiques (niveau d'alerte critique)
     */
    @Query("""
        SELECT ps FROM PatientSpecificity ps 
        WHERE ps.actif = true 
        AND ps.niveauAlerte = 'CRITICAL'
        ORDER BY ps.prioritePreleveur DESC
        """)
    List<PatientSpecificity> findCriticalSpecificities();

    /**
     * Spécificités pour une catégorie donnée (version simple)
     */
    List<PatientSpecificity> findByCategoryIdAndActifTrueOrderByPrioritePreleveurDesc(String categoryId);

    /**
     * Compter les spécificités actives
     */
    @Query("SELECT COUNT(ps) FROM PatientSpecificity ps WHERE ps.actif = true")
    long countActiveSpecificities();

    /**
     * Spécificités modifiant des analyses (VERSION CORRIGÉE POSTGRESQL)
     */
    @Query(value = """
        SELECT * FROM lims_referential.patient_specificities ps 
        WHERE ps.actif = true 
        AND ps.deleted_at IS NULL
        AND ps.analyses_modifiees IS NOT NULL
        AND jsonb_array_length(ps.analyses_modifiees) > 0
        """, nativeQuery = true)
    List<PatientSpecificity> findWithAnalysesModifiees();

    /**
     * Spécificités contre-indiquant des analyses (VERSION CORRIGÉE POSTGRESQL)
     */
    @Query(value = """
        SELECT * FROM lims_referential.patient_specificities ps 
        WHERE ps.actif = true 
        AND ps.deleted_at IS NULL
        AND ps.analyses_contre_indiquees IS NOT NULL
        AND jsonb_array_length(ps.analyses_contre_indiquees) > 0
        """, nativeQuery = true)
    List<PatientSpecificity> findWithAnalysesContreIndiquees();
}