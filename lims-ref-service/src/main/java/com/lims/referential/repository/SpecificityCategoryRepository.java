package com.lims.referential.repository;

import com.lims.referential.entity.SpecificityCategory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SpecificityCategoryRepository extends JpaRepository<SpecificityCategory, String> {

    /**
     * Recherche par nom
     */
    Optional<SpecificityCategory> findByNomAndActifTrue(String nom);

    /**
     * Toutes les catégories actives triées par ordre d'affichage
     */
    List<SpecificityCategory> findAllByActifTrueOrderByOrdreAffichage();

    /**
     * Catégories avec spécificités
     */
    @Query("""
        SELECT DISTINCT sc FROM SpecificityCategory sc 
        LEFT JOIN sc.specificities ps 
        WHERE sc.actif = true 
        AND ps.actif = true
        ORDER BY sc.ordreAffichage
        """)
    List<SpecificityCategory> findCategoriesWithActiveSpecificities();

    /**
     * Vérifier l'existence d'une catégorie
     */
    boolean existsByIdAndActifTrue(String id);
}