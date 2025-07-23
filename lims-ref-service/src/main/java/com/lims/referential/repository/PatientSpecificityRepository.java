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
     * Recherche textuelle
     */
    @Query("""
        SELECT ps FROM PatientSpecificity ps 
        WHERE ps.actif = true 
        AND (UPPER(ps.titre) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(ps.description) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR JSON_SEARCH(ps.motsCles, 'one', CONCAT('%', :searchTerm, '%')) IS NOT NULL)
        ORDER BY ps.prioritePreleveur DESC, ps.titre
        """)
    Page<PatientSpecificity> searchByTerm(@Param("searchTerm") String searchTerm, Pageable pageable);

    /**
     * Filtrage multi-critères
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
     * Spécificités affectant une analyse donnée
     */
    @Query("""
        SELECT ps FROM PatientSpecificity ps 
        WHERE ps.actif = true 
        AND (JSON_CONTAINS(ps.analysesContreIndiquees, JSON_QUOTE(:codeNabm))
             OR JSON_CONTAINS(ps.analysesModifiees, JSON_QUOTE(:codeNabm)))
        """)
    List<PatientSpecificity> findAffectingAnalyse(@Param("codeNabm") String codeNabm);

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
     * Recherche par mots-clés
     */
    @Query("""
        SELECT ps FROM PatientSpecificity ps 
        WHERE ps.actif = true 
        AND JSON_SEARCH(ps.motsCles, 'one', :motCle) IS NOT NULL
        """)
    List<PatientSpecificity> findByMotCle(@Param("motCle") String motCle);
}