package com.lims.referential.repository;

import com.lims.referential.entity.Analyse;
import com.lims.referential.enums.analyses.CategorieAnalyse;
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
public interface AnalyseRepository extends JpaRepository<Analyse, UUID> {

    /**
     * Recherche une analyse par son code NABM
     */
    Optional<Analyse> findByCodeNabmAndActifTrue(String codeNabm);

    /**
     * Recherche par catégorie
     */
    Page<Analyse> findByCategorieAndActifTrue(CategorieAnalyse categorie, Pageable pageable);

    /**
     * Recherche textuelle avec PostgreSQL full-text search
     */
    @Query("""
        SELECT a FROM Analyse a 
        WHERE a.actif = true 
        AND (UPPER(a.libelle) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(a.codeNabm) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(a.description) LIKE UPPER(CONCAT('%', :searchTerm, '%')))
        ORDER BY 
            CASE WHEN UPPER(a.codeNabm) = UPPER(:searchTerm) THEN 1
                 WHEN UPPER(a.libelle) = UPPER(:searchTerm) THEN 2
                 WHEN UPPER(a.codeNabm) LIKE UPPER(CONCAT(:searchTerm, '%')) THEN 3
                 WHEN UPPER(a.libelle) LIKE UPPER(CONCAT(:searchTerm, '%')) THEN 4
                 ELSE 5 END
        """)
    Page<Analyse> searchByTerm(@Param("searchTerm") String searchTerm, Pageable pageable);

    /**
     * Auto-complétion pour la recherche
     */
    @Query("""
        SELECT a FROM Analyse a 
        WHERE a.actif = true 
        AND (UPPER(a.libelle) LIKE UPPER(CONCAT(:prefix, '%'))
             OR UPPER(a.codeNabm) LIKE UPPER(CONCAT(:prefix, '%')))
        ORDER BY 
            CASE WHEN UPPER(a.codeNabm) LIKE UPPER(CONCAT(:prefix, '%')) THEN 1
                 ELSE 2 END,
            LENGTH(a.libelle)
        """)
    List<Analyse> findSuggestions(@Param("prefix") String prefix, Pageable pageable);

    /**
     * Filtrage multi-critères
     */
    @Query("""
        SELECT a FROM Analyse a 
        WHERE a.actif = true
        AND (:categorie IS NULL OR a.categorie = :categorie)
        AND (:sousCategorie IS NULL OR UPPER(a.sousCategorie) = UPPER(:sousCategorie))
        AND (:actif IS NULL OR a.actif = :actif)
        """)
    Page<Analyse> findWithFilters(
            @Param("categorie") CategorieAnalyse categorie,
            @Param("sousCategorie") String sousCategorie,
            @Param("actif") Boolean actif,
            Pageable pageable);

    /**
     * Statistiques des analyses
     */
    @Query("SELECT COUNT(a) FROM Analyse a WHERE a.actif = true")
    long countActiveAnalyses();

    @Query("SELECT a.categorie, COUNT(a) FROM Analyse a WHERE a.actif = true GROUP BY a.categorie")
    List<Object[]> getAnalysesByCategory();
}