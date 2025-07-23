// MedecinRepository.java
package com.lims.referential.repository;

import com.lims.referential.entity.Medecin;
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
public interface MedecinRepository extends JpaRepository<Medecin, UUID> {

    /**
     * Recherche un médecin par son numéro RPPS
     */
    Optional<Medecin> findByNumeroRppsAndActifTrue(String numeroRpps);

    /**
     * Recherche par spécialité principale
     */
    Page<Medecin> findBySpecialitePrincipaleAndActifTrue(String specialite, Pageable pageable);

    /**
     * Recherche par ville
     */
    Page<Medecin> findByAdresse_VilleAndActifTrue(String ville, Pageable pageable);

    /**
     * Recherche par département
     */
    Page<Medecin> findByAdresse_DepartementAndActifTrue(String departement, Pageable pageable);

    /**
     * Recherche textuelle avec PostgreSQL full-text search
     */
    @Query("""
        SELECT m FROM Medecin m 
        WHERE m.actif = true 
        AND (UPPER(m.nom) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(m.prenom) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(m.numeroRpps) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(m.specialitePrincipale) LIKE UPPER(CONCAT('%', :searchTerm, '%')))
        ORDER BY 
            CASE WHEN UPPER(m.numeroRpps) = UPPER(:searchTerm) THEN 1
                 WHEN UPPER(m.nom) = UPPER(:searchTerm) THEN 2
                 WHEN UPPER(m.nom) LIKE UPPER(CONCAT(:searchTerm, '%')) THEN 3
                 WHEN UPPER(m.prenom) LIKE UPPER(CONCAT(:searchTerm, '%')) THEN 4
                 ELSE 5 END,
            m.nom, m.prenom
        """)
    Page<Medecin> searchByTerm(@Param("searchTerm") String searchTerm, Pageable pageable);

    /**
     * Auto-complétion pour la recherche
     */
    @Query("""
        SELECT m FROM Medecin m 
        WHERE m.actif = true 
        AND (UPPER(m.nom) LIKE UPPER(CONCAT(:prefix, '%'))
             OR UPPER(m.prenom) LIKE UPPER(CONCAT(:prefix, '%'))
             OR UPPER(m.numeroRpps) LIKE UPPER(CONCAT(:prefix, '%')))
        ORDER BY m.nom, m.prenom
        """)
    List<Medecin> findSuggestions(@Param("prefix") String prefix, Pageable pageable);

    /**
     * Filtrage multi-critères
     */
    @Query("""
        SELECT m FROM Medecin m 
        WHERE m.actif = true
        AND (:specialite IS NULL OR m.specialitePrincipale = :specialite)
        AND (:ville IS NULL OR UPPER(m.adresse.ville) = UPPER(:ville))
        AND (:departement IS NULL OR UPPER(m.adresse.departement) = UPPER(:departement))
        """)
    Page<Medecin> findWithFilters(
            @Param("specialite") String specialite,
            @Param("ville") String ville,
            @Param("departement") String departement,
            Pageable pageable);

    /**
     * Compter les médecins par spécialité
     */
    @Query("SELECT m.specialitePrincipale, COUNT(m) FROM Medecin m WHERE m.actif = true GROUP BY m.specialitePrincipale")
    List<Object[]> countBySpecialite();

    /**
     * Compter les médecins par département
     */
    @Query("SELECT m.adresse.departement, COUNT(m) FROM Medecin m WHERE m.actif = true GROUP BY m.adresse.departement")
    List<Object[]> countByDepartement();

    /**
     * Vérifier l'existence d'un RPPS
     */
    boolean existsByNumeroRppsAndActifTrue(String numeroRpps);
}

// MedicamentRepository.java


// MutuelleRepository.java


// GeographiqueRepository.java


// PatientSpecificityRepository.java


// SpecificityCategoryRepository.java
