package com.lims.referential.repository;

import com.lims.referential.entity.Laboratoire;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository pour la gestion des laboratoires en base de données.
 * Inclut les méthodes de recherche géographique et de filtrage.
 */
@Repository
public interface LaboratoireRepository extends JpaRepository<Laboratoire, UUID> {

    // ============================================
    // REQUÊTES DE BASE
    // ============================================

    /**
     * Trouve tous les laboratoires actifs (non supprimés)
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL")
    List<Laboratoire> findAllActive();

    /**
     * Trouve tous les laboratoires actifs avec pagination
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL")
    Page<Laboratoire> findAllActive(Pageable pageable);

    /**
     * Trouve un laboratoire actif par ID
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.id = :id AND l.actif = true AND l.deletedAt IS NULL")
    Optional<Laboratoire> findActiveById(@Param("id") UUID id);

    /**
     * Compte les laboratoires actifs
     */
    @Query("SELECT COUNT(l) FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL")
    long countActive();

    // ============================================
    // REQUÊTES DE RECHERCHE TEXTUELLE
    // ============================================

    /**
     * Recherche de laboratoires par terme (nom, ville, adresse)
     */
    @Query("""
        SELECT l FROM Laboratoire l 
        WHERE l.actif = true AND l.deletedAt IS NULL
        AND (LOWER(l.nom) LIKE LOWER(CONCAT('%', :searchTerm, '%'))
             OR LOWER(l.ville) LIKE LOWER(CONCAT('%', :searchTerm, '%'))
             OR LOWER(l.adresse) LIKE LOWER(CONCAT('%', :searchTerm, '%'))
             OR LOWER(l.codePostal) LIKE LOWER(CONCAT('%', :searchTerm, '%')))
        ORDER BY l.nom
        """)
    Page<Laboratoire> searchByTerm(@Param("searchTerm") String searchTerm, Pageable pageable);

    /**
     * Recherche par ville
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL AND LOWER(l.ville) = LOWER(:ville)")
    List<Laboratoire> findByVille(@Param("ville") String ville);

    /**
     * Recherche par code postal
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL AND l.codePostal = :codePostal")
    List<Laboratoire> findByCodePostal(@Param("codePostal") String codePostal);

    // ============================================
    // REQUÊTES GÉOGRAPHIQUES (SIMPLIFIÉES)
    // ============================================

    /**
     * Recherche géographique simplifiée par zone (à adapter selon vos coordonnées stockées)
     * Note: Cette implémentation est basique. Pour une vraie recherche géographique,
     * il faudrait stocker latitude/longitude et utiliser des fonctions spatiales.
     */
    @Query("""
        SELECT l FROM Laboratoire l 
        WHERE l.actif = true AND l.deletedAt IS NULL
        AND l.ville IN (
            SELECT DISTINCT l2.ville FROM Laboratoire l2 
            WHERE l2.actif = true AND l2.deletedAt IS NULL
        )
        ORDER BY l.ville, l.nom
        """)
    List<Laboratoire> findByGeolocation(
            @Param("latitude") BigDecimal latitude,
            @Param("longitude") BigDecimal longitude,
            @Param("radius") Integer radius);

    /**
     * Version alternative avec coordonnées géographiques (si vous avez ces champs)
     * Décommentez et adaptez si vous ajoutez latitude/longitude à l'entité
     */
    /*
    @Query(value = """
        SELECT * FROM lims_referential.laboratoires l
        WHERE l.actif = true AND l.deleted_at IS NULL
        AND ST_DWithin(
            ST_SetSRID(ST_Point(l.longitude, l.latitude), 4326),
            ST_SetSRID(ST_Point(:longitude, :latitude), 4326),
            :radius * 1000
        )
        ORDER BY ST_Distance(
            ST_SetSRID(ST_Point(l.longitude, l.latitude), 4326),
            ST_SetSRID(ST_Point(:longitude, :latitude), 4326)
        )
        """, nativeQuery = true)
    List<Laboratoire> findByGeolocationExact(
            @Param("latitude") BigDecimal latitude,
            @Param("longitude") BigDecimal longitude,
            @Param("radius") Integer radius);
    */

    // ============================================
    // REQUÊTES PAR CAPACITÉS TECHNIQUES
    // ============================================

    /**
     * Trouve les laboratoires proposant une analyse spécifique
     */
    @Query("""
        SELECT DISTINCT l FROM Laboratoire l 
        JOIN l.analysesDisponibles a
        WHERE l.actif = true AND l.deletedAt IS NULL
        AND a = :codeAnalyse
        ORDER BY l.nom
        """)
    List<Laboratoire> findByAnalyseDisponible(@Param("codeAnalyse") String codeAnalyse);

    /**
     * Trouve les laboratoires ayant une spécialité technique
     */
    @Query("""
        SELECT DISTINCT l FROM Laboratoire l 
        JOIN l.specialitesTechniques s
        WHERE l.actif = true AND l.deletedAt IS NULL
        AND s = :specialite
        ORDER BY l.nom
        """)
    List<Laboratoire> findBySpecialiteTechnique(@Param("specialite") String specialite);

    /**
     * Trouve les laboratoires avec un équipement spécial
     */
    @Query("""
        SELECT DISTINCT l FROM Laboratoire l 
        JOIN l.equipementsSpeciaux e
        WHERE l.actif = true AND l.deletedAt IS NULL
        AND e = :equipement
        ORDER BY l.nom
        """)
    List<Laboratoire> findByEquipementSpecial(@Param("equipement") String equipement);

    // ============================================
    // REQUÊTES DE COMMODITÉS
    // ============================================

    /**
     * Trouve les laboratoires avec parking
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL AND l.parkingDisponible = true")
    List<Laboratoire> findWithParking();

    /**
     * Trouve les laboratoires accessibles aux handicapés
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL AND l.accesHandicapes = true")
    List<Laboratoire> findAccessibleToDisabled();

    /**
     * Trouve les laboratoires avec transport public
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL AND l.transportPublic IS NOT NULL")
    List<Laboratoire> findWithPublicTransport();

    // ============================================
    // REQUÊTES STATISTIQUES
    // ============================================

    /**
     * Statistiques par ville
     */
    @Query("""
        SELECT l.ville, COUNT(l) 
        FROM Laboratoire l 
        WHERE l.actif = true AND l.deletedAt IS NULL
        GROUP BY l.ville 
        ORDER BY COUNT(l) DESC
        """)
    List<Object[]> countByVille();

    /**
     * Nombre d'analyses disponibles par laboratoire
     */
    @Query("""
        SELECT l.nom, SIZE(l.analysesDisponibles)
        FROM Laboratoire l 
        WHERE l.actif = true AND l.deletedAt IS NULL
        ORDER BY SIZE(l.analysesDisponibles) DESC
        """)
    List<Object[]> countAnalysesByLaboratoire();

    // ============================================
    // REQUÊTES DE MAINTENANCE
    // ============================================

    /**
     * Trouve les laboratoires sans email
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL AND (l.email IS NULL OR l.email = '')")
    List<Laboratoire> findWithoutEmail();

    /**
     * Trouve les laboratoires sans analyses disponibles
     */
    @Query(value = """
        SELECT * FROM lims_referential.laboratoires l 
        WHERE l.actif = true 
        AND l.deleted_at IS NULL 
        AND (l.analyses_disponibles IS NULL OR l.analyses_disponibles = '[]'::jsonb)
        """, nativeQuery = true)
    List<Laboratoire> findWithoutAnalyses();

    /**
     * Supprime définitivement les laboratoires marqués comme supprimés depuis plus de X jours
     */
    @Query("DELETE FROM Laboratoire l WHERE l.deletedAt IS NOT NULL AND l.deletedAt < :cutoffDate")
    void permanentlyDeleteOldSoftDeleted(@Param("cutoffDate") java.time.LocalDateTime cutoffDate);
}