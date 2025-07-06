package com.lims.patient.repository;

import com.lims.patient.entity.OrdonnanceAnalyse;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

/**
 * Repository pour les analyses d'ordonnance
 */
@Repository
public interface OrdonnanceAnalyseRepository extends JpaRepository<OrdonnanceAnalyse, UUID> {

    /**
     * Trouve toutes les analyses d'une ordonnance
     */
    List<OrdonnanceAnalyse> findByOrdonnanceIdOrderByEstUrgentDescDateCreationAsc(UUID ordonnanceId);

    /**
     * Compte les analyses par code
     */
    @Query("SELECT oa.codeAnalyse, COUNT(oa) FROM OrdonnanceAnalyse oa " +
            "WHERE oa.ordonnance.dateSuppression IS NULL " +
            "GROUP BY oa.codeAnalyse ORDER BY COUNT(oa) DESC")
    List<Object[]> countByCodeAnalyse();
}
