package com.lims.patient.repository;

import com.lims.patient.entity.Patient;
import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.PatientStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository pour les patients - Version harmonisée avec l'architecture des services
 * Supporte les Specifications pour les recherches complexes + méthodes simples optimisées
 */
@Repository
public interface PatientRepository extends JpaRepository<Patient, UUID>, JpaSpecificationExecutor<Patient> {

    // ===============================================================
    // RECHERCHES DE BASE CRITIQUES (utilisées par PatientService)
    // ===============================================================

    /**
     * Trouve un patient par ID (non supprimé)
     * Utilisé par: PatientService.getPatient()
     */
    Optional<Patient> findByIdAndDateSuppressionIsNull(UUID id);

    /**
     * Trouve un patient par numéro de sécurité sociale (non supprimé)
     * Utilisé par: PatientService.findByNumeroSecu()
     */
    Optional<Patient> findByNumeroSecuAndDateSuppressionIsNull(String numeroSecu);

    /**
     * Trouve un patient par email (égalité exacte, insensible à la casse, non supprimé)
     * Utilisé par: PatientService.findByEmail()
     */
    Optional<Patient> findByEmailIgnoreCaseAndDateSuppressionIsNull(String email);

    /**
     * Version alternative pour la compatibilité (nom exact utilisé dans le service)
     */
    default Optional<Patient> findByEmailAndDateSuppressionIsNull(String email) {
        return findByEmailIgnoreCaseAndDateSuppressionIsNull(email);
    }

    /**
     * Trouve un patient par téléphone (non supprimé)
     * Utilisé par: PatientService.findByTelephone()
     */
    Optional<Patient> findByTelephoneAndDateSuppressionIsNull(String telephone);

    // ===============================================================
    // VÉRIFICATIONS D'EXISTENCE (utilisées par PatientService)
    // ===============================================================

    /**
     * Vérifie si un patient existe avec ce numéro de sécurité sociale
     * Utilisé par: PatientService.existsByNumeroSecu()
     */
    boolean existsByNumeroSecuAndDateSuppressionIsNull(String numeroSecu);

    /**
     * Vérifie si un patient existe avec cet email (insensible à la casse)
     * Utilisé par: PatientService.existsByEmail()
     */
    boolean existsByEmailIgnoreCaseAndDateSuppressionIsNull(String email);

    /**
     * Version alternative pour la compatibilité
     */
    default boolean existsByEmailAndDateSuppressionIsNull(String email) {
        return existsByEmailIgnoreCaseAndDateSuppressionIsNull(email);
    }

    /**
     * Vérifie si un patient existe avec ce téléphone
     * Utilisé par: PatientService.existsByTelephone()
     */
    boolean existsByTelephoneAndDateSuppressionIsNull(String telephone);

    // ===============================================================
    // RECHERCHES PAR STATUT (utilisées par PatientService)
    // ===============================================================

    /**
     * Trouve tous les patients par statut avec pagination
     * Utilisé par: PatientService.getActivePatients()
     */
    Page<Patient> findByStatutAndDateSuppressionIsNull(PatientStatus statut, Pageable pageable);

    /**
     * Trouve tous les patients par statut (sans pagination)
     */
    List<Patient> findByStatutAndDateSuppressionIsNull(PatientStatus statut);

    /**
     * Compte les patients par statut
     * Utilisé par: PatientService.countActivePatients()
     */
    long countByStatutAndDateSuppressionIsNull(PatientStatus statut);

    // ===============================================================
    // RECHERCHES SPÉCIALISÉES OPTIMISÉES (pour PatientSearchService)
    // ===============================================================

    /**
     * Recherche optimisée par nom (pour autocomplétion rapide)
     * Note: Les recherches complexes utilisent les Specifications
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "LOWER(p.nom) LIKE LOWER(CONCAT('%', :nom, '%')) AND " +
            "p.dateSuppression IS NULL " +
            "ORDER BY p.nom, p.prenom")
    List<Patient> findByNomContainingIgnoreCase(@Param("nom") String nom, Pageable pageable);

    /**
     * Recherche optimisée par prénom (pour autocomplétion rapide)
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "LOWER(p.prenom) LIKE LOWER(CONCAT('%', :prenom, '%')) AND " +
            "p.dateSuppression IS NULL " +
            "ORDER BY p.prenom, p.nom")
    List<Patient> findByPrenomContainingIgnoreCase(@Param("prenom") String prenom, Pageable pageable);

    /**
     * Recherche optimisée par nom complet (concaténation nom + prénom)
     * Utilisé pour les suggestions d'autocomplétion
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "(LOWER(CONCAT(p.nom, ' ', p.prenom)) LIKE LOWER(CONCAT('%', :nomComplet, '%')) OR " +
            " LOWER(CONCAT(p.prenom, ' ', p.nom)) LIKE LOWER(CONCAT('%', :nomComplet, '%'))) AND " +
            "p.dateSuppression IS NULL " +
            "ORDER BY p.nom, p.prenom")
    List<Patient> findByNomCompletContaining(@Param("nomComplet") String nomComplet, Pageable pageable);

    /**
     * Recherche par ville (pour filtres rapides)
     */
    List<Patient> findByVilleContainingIgnoreCaseAndDateSuppressionIsNull(String ville);

    /**
     * Recherche par code postal (pour filtres géographiques)
     */
    List<Patient> findByCodePostalAndDateSuppressionIsNull(String codePostal);

    /**
     * Recherche par date de naissance exacte
     */
    List<Patient> findByDateNaissanceAndDateSuppressionIsNull(LocalDate dateNaissance);

    /**
     * Recherche par sexe
     */
    List<Patient> findBySexeAndDateSuppressionIsNull(GenderType sexe);

    // ===============================================================
    // RECHERCHES MÉTIER SPÉCIALISÉES
    // ===============================================================

    /**
     * Trouve les patients avec notifications activées
     * Utilisé pour les campagnes de communication
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateSuppression IS NULL AND " +
            "p.statut = :statut AND " +
            "(p.consentementEmail = true OR p.consentementSms = true)")
    List<Patient> findPatientsWithNotificationsEnabled(@Param("statut") PatientStatus statut);

    /**
     * Trouve les patients par tranche d'âge
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateSuppression IS NULL AND " +
            "p.dateNaissance BETWEEN :dateNaissanceMin AND :dateNaissanceMax " +
            "ORDER BY p.dateNaissance DESC")
    List<Patient> findByAgeRange(@Param("dateNaissanceMin") LocalDate dateNaissanceMin,
                                 @Param("dateNaissanceMax") LocalDate dateNaissanceMax);

    /**
     * Trouve les patients créés récemment
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateCreation >= :dateLimit AND " +
            "p.dateSuppression IS NULL " +
            "ORDER BY p.dateCreation DESC")
    List<Patient> findRecentlyCreatedPatients(@Param("dateLimit") LocalDateTime dateLimit);

    /**
     * Trouve les patients récemment modifiés
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateModification >= :dateLimit AND " +
            "p.dateSuppression IS NULL " +
            "ORDER BY p.dateModification DESC")
    List<Patient> findRecentlyModifiedPatients(@Param("dateLimit") LocalDateTime dateLimit);

    // ===============================================================
    // RECHERCHES GÉOGRAPHIQUES
    // ===============================================================

    /**
     * Recherche par département (basé sur le code postal)
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.codePostal LIKE CONCAT(:codeDepartement, '%') AND " +
            "p.dateSuppression IS NULL")
    List<Patient> findByDepartement(@Param("codeDepartement") String codeDepartement);

    /**
     * Recherche par région
     */
    List<Patient> findByRegionAndDateSuppressionIsNull(String region);

    /**
     * Recherche par proximité géographique (si vous avez des coordonnées GPS)
     */
    @Query(value = "SELECT * FROM lims_patient.patients p WHERE " +
            "p.date_suppression IS NULL AND " +
            "p.latitude IS NOT NULL AND p.longitude IS NOT NULL AND " +
            "ST_DWithin(ST_MakePoint(p.longitude, p.latitude)::geography, " +
            "ST_MakePoint(:longitude, :latitude)::geography, :rayonMetres)",
            nativeQuery = true)
    List<Patient> findByProximity(@Param("latitude") Double latitude,
                                  @Param("longitude") Double longitude,
                                  @Param("rayonMetres") Double rayonMetres);

    // ===============================================================
    // STATISTIQUES (utilisées par PatientSearchService)
    // ===============================================================

    /**
     * Compte le nombre total de patients actifs
     * Utilisé par: PatientSearchService.countActivePatients()
     */
    @Query("SELECT COUNT(p) FROM Patient p WHERE p.dateSuppression IS NULL AND p.statut = 'ACTIF'")
    long countActivePatients();

    /**
     * Statistiques par statut
     * Utilisé par: PatientSearchService.getPatientStatisticsByStatus()
     */
    @Query("SELECT p.statut, COUNT(p) FROM Patient p WHERE p.dateSuppression IS NULL GROUP BY p.statut")
    List<Object[]> countPatientsByStatus();

    /**
     * Statistiques par sexe
     * Utilisé par: PatientSearchService.getPatientStatisticsByGender()
     */
    @Query("SELECT p.sexe, COUNT(p) FROM Patient p WHERE p.dateSuppression IS NULL GROUP BY p.sexe")
    List<Object[]> countPatientsByGender();

    /**
     * Statistiques par ville (top 10)
     * Utilisé par: PatientSearchService.getPatientStatisticsByCity()
     */
    @Query("SELECT p.ville, COUNT(p) FROM Patient p WHERE " +
            "p.dateSuppression IS NULL AND p.ville IS NOT NULL " +
            "GROUP BY p.ville ORDER BY COUNT(p) DESC")
    List<Object[]> countPatientsByCity();

    /**
     * Statistiques par tranche d'âge
     */
    @Query("SELECT " +
            "CASE " +
            "  WHEN EXTRACT(YEAR FROM CURRENT_DATE) - EXTRACT(YEAR FROM p.dateNaissance) < 18 THEN 'Moins de 18 ans' " +
            "  WHEN EXTRACT(YEAR FROM CURRENT_DATE) - EXTRACT(YEAR FROM p.dateNaissance) BETWEEN 18 AND 30 THEN '18-30 ans' " +
            "  WHEN EXTRACT(YEAR FROM CURRENT_DATE) - EXTRACT(YEAR FROM p.dateNaissance) BETWEEN 31 AND 50 THEN '31-50 ans' " +
            "  WHEN EXTRACT(YEAR FROM CURRENT_DATE) - EXTRACT(YEAR FROM p.dateNaissance) BETWEEN 51 AND 70 THEN '51-70 ans' " +
            "  ELSE 'Plus de 70 ans' " +
            "END AS trancheAge, COUNT(p) " +
            "FROM Patient p WHERE p.dateSuppression IS NULL AND p.dateNaissance IS NOT NULL " +
            "GROUP BY " +
            "CASE " +
            "  WHEN EXTRACT(YEAR FROM CURRENT_DATE) - EXTRACT(YEAR FROM p.dateNaissance) < 18 THEN 'Moins de 18 ans' " +
            "  WHEN EXTRACT(YEAR FROM CURRENT_DATE) - EXTRACT(YEAR FROM p.dateNaissance) BETWEEN 18 AND 30 THEN '18-30 ans' " +
            "  WHEN EXTRACT(YEAR FROM CURRENT_DATE) - EXTRACT(YEAR FROM p.dateNaissance) BETWEEN 31 AND 50 THEN '31-50 ans' " +
            "  WHEN EXTRACT(YEAR FROM CURRENT_DATE) - EXTRACT(YEAR FROM p.dateNaissance) BETWEEN 51 AND 70 THEN '51-70 ans' " +
            "  ELSE 'Plus de 70 ans' " +
            "END")
    List<Object[]> countPatientsByAgeRange();

    /**
     * Statistiques d'évolution (nouveaux patients par mois)
     */
    @Query("SELECT " +
            "EXTRACT(YEAR FROM p.dateCreation) as annee, " +
            "EXTRACT(MONTH FROM p.dateCreation) as mois, " +
            "COUNT(p) as nombrePatients " +
            "FROM Patient p WHERE " +
            "p.dateSuppression IS NULL AND " +
            "p.dateCreation >= :dateDebut " +
            "GROUP BY EXTRACT(YEAR FROM p.dateCreation), EXTRACT(MONTH FROM p.dateCreation) " +
            "ORDER BY annee DESC, mois DESC")
    List<Object[]> countNewPatientsByMonth(@Param("dateDebut") LocalDateTime dateDebut);

    // ===============================================================
    // REQUÊTES DE MAINTENANCE ET AUDIT
    // ===============================================================

    /**
     * Trouve les doublons potentiels par nom/prénom/date de naissance
     */
    @Query("SELECT p1 FROM Patient p1 WHERE EXISTS (" +
            "SELECT p2 FROM Patient p2 WHERE " +
            "p1.id != p2.id AND " +
            "p1.dateSuppression IS NULL AND p2.dateSuppression IS NULL AND " +
            "LOWER(p1.nom) = LOWER(p2.nom) AND " +
            "LOWER(p1.prenom) = LOWER(p2.prenom) AND " +
            "p1.dateNaissance = p2.dateNaissance)")
    List<Patient> findPotentialDuplicates();

    /**
     * Trouve les patients avec des données incomplètes
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateSuppression IS NULL AND " +
            "(p.email IS NULL OR p.telephone IS NULL OR p.ville IS NULL)")
    List<Patient> findPatientsWithIncompleteData();

    /**
     * Trouve les patients inactifs depuis longtemps
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateSuppression IS NULL AND " +
            "p.statut = 'INACTIF' AND " +
            "p.dateModification < :dateLimit")
    List<Patient> findLongInactivePatients(@Param("dateLimit") LocalDateTime dateLimit);

    // ===============================================================
    // MÉTHODES UTILITAIRES
    // ===============================================================

    /**
     * Compte le nombre total de patients (incluant supprimés)
     */
    @Query("SELECT COUNT(p) FROM Patient p")
    long countAllPatients();

    /**
     * Compte le nombre de patients supprimés
     */
    @Query("SELECT COUNT(p) FROM Patient p WHERE p.dateSuppression IS NOT NULL")
    long countDeletedPatients();

    /**
     * Trouve les patients créés par un utilisateur spécifique
     */
    List<Patient> findByCreeParAndDateSuppressionIsNull(String creePar);

    /**
     * Recherche full-text simple (si votre base de données le supporte)
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateSuppression IS NULL AND " +
            "(LOWER(p.nom) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            " LOWER(p.prenom) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            " LOWER(p.email) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            " p.telephone LIKE CONCAT('%', :searchTerm, '%') OR " +
            " LOWER(p.ville) LIKE LOWER(CONCAT('%', :searchTerm, '%')))")
    List<Patient> findByFullTextSearch(@Param("searchTerm") String searchTerm, Pageable pageable);

    // NOTE IMPORTANTE:
    // Les recherches complexes multicritères se font maintenant avec les Specifications
    // dans PatientSpecifications, ce qui offre plus de flexibilité et de performance
}