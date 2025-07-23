package com.lims.referential.repository;

import com.lims.referential.entity.Medicament;
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
 * Repository pour la gestion des médicaments en base de données.
 * Utilise Spring Data JPA pour les opérations CRUD.
 */
@Repository
public interface MedicamentRepository extends JpaRepository<Medicament, UUID> {

    // ============================================
    // REQUÊTES DE BASE
    // ============================================

    /**
     * Trouve un médicament par son code CIS
     */
    Optional<Medicament> findByCodeCis(String codeCis);

    /**
     * Vérifie si un médicament existe avec le code CIS donné
     */
    boolean existsByCodeCis(String codeCis);

    /**
     * Récupère tous les médicaments actifs
     */
    List<Medicament> findByActifTrue();

    /**
     * Récupère tous les médicaments actifs avec pagination
     */
    Page<Medicament> findByActifTrue(Pageable pageable);

    /**
     * Compte le nombre de médicaments actifs
     */
    long countByActifTrue();

    // ============================================
    // REQUÊTES DE RECHERCHE
    // ============================================

    /**
     * Recherche de médicaments par dénomination (case insensitive)
     */
    List<Medicament> findByDenominationContainingIgnoreCase(String denomination);

    /**
     * Recherche de médicaments par laboratoire titulaire
     */
    List<Medicament> findByLaboratoireTitulaireContainingIgnoreCase(String laboratoire);

    /**
     * Recherche de médicaments par forme pharmaceutique
     */
    List<Medicament> findByFormePharmaContainingIgnoreCase(String formePharma);

    // ============================================
    // REQUÊTES SPÉCIALISÉES
    // ============================================

    /**
     * Récupère les médicaments remboursés (taux > 0)
     */
    List<Medicament> findByTauxRemboursementGreaterThan(Integer taux);

    /**
     * Récupère les médicaments sous surveillance renforcée
     */
    List<Medicament> findBySurveillanceRenforceeTrue();

    /**
     * Récupère les médicaments par statut AMM
     */
    List<Medicament> findByStatutAmm(String statutAmm);

    /**
     * Récupère les médicaments par statut BdM
     */
    List<Medicament> findByStatutBdm(String statutBdm);

    // ============================================
    // REQUÊTES NATIVES PERSONNALISÉES
    // ============================================

    /**
     * Recherche full-text dans plusieurs champs
     */
    @Query("""
        SELECT m FROM Medicament m 
        WHERE (LOWER(m.denomination) LIKE LOWER(CONCAT('%', :searchTerm, '%'))
           OR LOWER(m.laboratoireTitulaire) LIKE LOWER(CONCAT('%', :searchTerm, '%'))
           OR LOWER(m.laboratoireExploitant) LIKE LOWER(CONCAT('%', :searchTerm, '%'))
           OR m.codeCis LIKE UPPER(CONCAT('%', :searchTerm, '%')))
        AND m.actif = true
        ORDER BY m.denomination
        """)
    List<Medicament> searchMedicaments(@Param("searchTerm") String searchTerm);

    /**
     * Récupère les médicaments avec un taux de remboursement spécifique
     */
    @Query("SELECT m FROM Medicament m WHERE m.tauxRemboursement = :taux AND m.actif = true")
    List<Medicament> findByTauxRemboursementExact(@Param("taux") Integer taux);

    /**
     * Récupère les médicaments les plus récents
     */
    @Query("SELECT m FROM Medicament m WHERE m.actif = true ORDER BY m.dateCreation DESC")
    List<Medicament> findRecentMedicaments(Pageable pageable);

    /**
     * Statistiques : nombre de médicaments par laboratoire
     */
    @Query("""
        SELECT m.laboratoireTitulaire, COUNT(m) 
        FROM Medicament m 
        WHERE m.actif = true 
        GROUP BY m.laboratoireTitulaire 
        ORDER BY COUNT(m) DESC
        """)
    List<Object[]> countMedicamentsByLaboratoire();

    /**
     * Statistiques : répartition par forme pharmaceutique
     */
    @Query("""
        SELECT m.formePharma, COUNT(m) 
        FROM Medicament m 
        WHERE m.actif = true AND m.formePharma IS NOT NULL
        GROUP BY m.formePharma 
        ORDER BY COUNT(m) DESC
        """)
    List<Object[]> countMedicamentsByFormePharma();

    // ============================================
    // REQUÊTES DE MAINTENANCE
    // ============================================

    /**
     * Trouve les médicaments sans prix de vente
     */
    @Query("SELECT m FROM Medicament m WHERE m.prixVente IS NULL AND m.actif = true")
    List<Medicament> findMedicamentsSansPrix();

    /**
     * Trouve les médicaments avec des données incomplètes
     */
    @Query("""
        SELECT m FROM Medicament m 
        WHERE m.actif = true 
        AND (m.denomination IS NULL OR m.denomination = '' 
             OR m.laboratoireTitulaire IS NULL OR m.laboratoireTitulaire = '')
        """)
    List<Medicament> findMedicamentsAvecDonneesIncompletes();

    /**
     * Supprime les médicaments inactifs (nettoyage)
     */
    @Query("DELETE FROM Medicament m WHERE m.actif = false")
    void deleteInactifs();
}