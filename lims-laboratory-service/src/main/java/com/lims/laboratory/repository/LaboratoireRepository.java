package com.lims.laboratory.repository;

import com.lims.laboratory.entity.Laboratoire;
import com.lims.laboratory.entity.Laboratoire.TypeLaboratoire;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository pour l'entité Laboratoire
 */
@Repository
public interface LaboratoireRepository extends JpaRepository<Laboratoire, UUID>, JpaSpecificationExecutor<Laboratoire> {

    // === Recherches par identifiants uniques ===

    /**
     * Recherche un laboratoire par son numéro SIRET
     */
    Optional<Laboratoire> findBySiret(String siret);

    /**
     * Recherche un laboratoire par son numéro FINESS
     */
    Optional<Laboratoire> findByNumeroFiness(String numeroFiness);

    /**
     * Recherche un laboratoire par son code interne
     */
    Optional<Laboratoire> findByCodeLaboratoire(String codeLaboratoire);

    // === Vérifications d'unicité ===

    /**
     * Vérifie si un SIRET existe déjà (excluant un laboratoire spécifique)
     */
    boolean existsBySiretAndIdNot(String siret, UUID id);

    /**
     * Vérifie si un numéro FINESS existe déjà (excluant un laboratoire spécifique)
     */
    boolean existsByNumeroFinessAndIdNot(String numeroFiness, UUID id);

    /**
     * Vérifie si un code laboratoire existe déjà (excluant un laboratoire spécifique)
     */
    boolean existsByCodeLaboratoireAndIdNot(String codeLaboratoire, UUID id);

    // === Recherches par statut ===

    /**
     * Recherche tous les laboratoires actifs
     */
    List<Laboratoire> findByActifTrue();

    /**
     * Recherche tous les laboratoires par statut
     */
    List<Laboratoire> findByActif(Boolean actif);

    // === Recherches par type ===

    /**
     * Recherche par type de laboratoire
     */
    List<Laboratoire> findByTypeLaboratoire(TypeLaboratoire typeLaboratoire);

    /**
     * Recherche par type et statut
     */
    List<Laboratoire> findByTypeLaboratoireAndActif(TypeLaboratoire typeLaboratoire, Boolean actif);

    // === Recherches textuelles ===

    /**
     * Recherche textuelle dans les noms et codes (avec pagination)
     */
    @Query("""
        SELECT l FROM Laboratoire l 
        WHERE (:searchTerm IS NULL OR 
               LOWER(l.nomCommercial) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR
               LOWER(l.nomLegal) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR
               LOWER(l.nomLaboratoire) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR
               LOWER(l.codeLaboratoire) LIKE LOWER(CONCAT('%', :searchTerm, '%')))
        """)
    Page<Laboratoire> findBySearchTerm(@Param("searchTerm") String searchTerm, Pageable pageable);

    /**
     * Recherche avancée avec plusieurs critères
     */
    @Query("""
        SELECT l FROM Laboratoire l 
        WHERE (:searchTerm IS NULL OR 
               LOWER(l.nomCommercial) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR
               LOWER(l.nomLegal) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR
               LOWER(l.nomLaboratoire) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR
               LOWER(l.codeLaboratoire) LIKE LOWER(CONCAT('%', :searchTerm, '%')))
        AND (:typeLaboratoire IS NULL OR l.typeLaboratoire = :typeLaboratoire)
        AND (:actif IS NULL OR l.actif = :actif)
        AND (:siret IS NULL OR l.siret = :siret)
        AND (:numeroFiness IS NULL OR l.numeroFiness = :numeroFiness)
        ORDER BY l.nomCommercial ASC
        """)
    Page<Laboratoire> findWithCriteria(
            @Param("searchTerm") String searchTerm,
            @Param("typeLaboratoire") TypeLaboratoire typeLaboratoire,
            @Param("actif") Boolean actif,
            @Param("siret") String siret,
            @Param("numeroFiness") String numeroFiness,
            Pageable pageable
    );

    // === Statistiques ===

    /**
     * Compte les laboratoires actifs
     */
    long countByActifTrue();

    /**
     * Compte les laboratoires par type
     */
    long countByTypeLaboratoire(TypeLaboratoire typeLaboratoire);

    /**
     * Statistiques par type de laboratoire
     */
    @Query("""
        SELECT l.typeLaboratoire, COUNT(l) 
        FROM Laboratoire l 
        WHERE l.actif = true
        GROUP BY l.typeLaboratoire
        """)
    List<Object[]> getStatistiquesByType();
}