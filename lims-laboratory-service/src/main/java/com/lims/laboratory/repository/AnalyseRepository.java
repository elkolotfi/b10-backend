package com.lims.laboratory.repository;

import com.lims.laboratory.entity.LaboratoireAnalyse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AnalyseRepository extends JpaRepository<LaboratoireAnalyse, UUID> {

    // === RECHERCHE PAR LABORATOIRE ===

    List<LaboratoireAnalyse> findByLaboratoireIdAndAnalyseActiveTrue(UUID laboratoireId);

    List<LaboratoireAnalyse> findByLaboratoireId(UUID laboratoireId);

    // === RECHERCHE PAR EXAMEN ===

    List<LaboratoireAnalyse> findByLaboratoireExamenIdAndAnalyseActiveTrue(UUID laboratoireExamenId);

    List<LaboratoireAnalyse> findByLaboratoireExamenId(UUID laboratoireExamenId);

    // === RECHERCHE PAR CODES ===

    Optional<LaboratoireAnalyse> findByLaboratoireIdAndCodeAnalyseLabo(UUID laboratoireId, String codeAnalyseLabo);

    boolean existsByLaboratoireIdAndCodeAnalyseLabo(UUID laboratoireId, String codeAnalyseLabo);

    // === RECHERCHE PAR RÉFÉRENTIEL ===

    Optional<LaboratoireAnalyse> findByLaboratoireIdAndAnalyseReferentielId(UUID laboratoireId, UUID analyseReferentielId);

    // === RECHERCHE COMPLEXE ===

    @Query("""
        SELECT a FROM LaboratoireAnalyse a
        WHERE (:laboratoireId IS NULL OR a.laboratoireId = :laboratoireId)
        AND (:laboratoireExamenId IS NULL OR a.laboratoireExamenId = :laboratoireExamenId)
        AND (:nomAnalyse IS NULL OR LOWER(a.nomAnalyseLabo) LIKE LOWER(CONCAT('%', :nomAnalyse, '%')))
        AND (:codeAnalyse IS NULL OR LOWER(a.codeAnalyseLabo) LIKE LOWER(CONCAT('%', :codeAnalyse, '%')))
        AND (:analyseActive IS NULL OR a.analyseActive = :analyseActive)
        AND (:sousTraite IS NULL OR a.sousTraite = :sousTraite)
        AND (:technique IS NULL OR LOWER(a.techniqueUtilisee) LIKE LOWER(CONCAT('%', :technique, '%')))
        AND (:automate IS NULL OR LOWER(a.automateUtilise) LIKE LOWER(CONCAT('%', :automate, '%')))
        ORDER BY a.nomAnalyseLabo
        """)
    Page<LaboratoireAnalyse> findAnalysesWithCriteria(
            @Param("laboratoireId") UUID laboratoireId,
            @Param("laboratoireExamenId") UUID laboratoireExamenId,
            @Param("nomAnalyse") String nomAnalyse,
            @Param("codeAnalyse") String codeAnalyse,
            @Param("analyseActive") Boolean analyseActive,
            @Param("sousTraite") Boolean sousTraite,
            @Param("technique") String technique,
            @Param("automate") String automate,
            Pageable pageable
    );

    // === STATISTIQUES ===

    @Query("SELECT COUNT(a) FROM LaboratoireAnalyse a WHERE a.laboratoireId = :laboratoireId AND a.analyseActive = true")
    long countActiveAnalysesByLaboratoire(@Param("laboratoireId") UUID laboratoireId);

    @Query("SELECT COUNT(a) FROM LaboratoireAnalyse a WHERE a.laboratoireId = :laboratoireId AND a.sousTraite = true")
    long countSousTraiteesByLaboratoire(@Param("laboratoireId") UUID laboratoireId);

    @Query("""
        SELECT a.sousTraite, COUNT(a) 
        FROM LaboratoireAnalyse a 
        WHERE a.laboratoireId = :laboratoireId AND a.analyseActive = true
        GROUP BY a.sousTraite
        """)
    List<Object[]> getStatistiquesSousTraitance(@Param("laboratoireId") UUID laboratoireId);
}