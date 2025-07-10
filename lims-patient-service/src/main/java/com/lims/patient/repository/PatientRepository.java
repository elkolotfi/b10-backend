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
 * Repository pour les patients - Version avec Specifications
 */
@Repository
public interface PatientRepository extends JpaRepository<Patient, UUID>, JpaSpecificationExecutor<Patient> {

    // ===== RECHERCHES DE BASE SIMPLES =====

    /**
     * Trouve un patient par ID (non supprimé)
     */
    Optional<Patient> findByIdAndDateSuppressionIsNull(UUID id);

    /**
     * Trouve un patient par numéro de sécurité sociale
     */
    Optional<Patient> findByNumeroSecuAndDateSuppressionIsNull(String numeroSecu);

    /**
     * Trouve un patient par email (égalité exacte)
     */
    Optional<Patient> findByEmailIgnoreCaseAndDateSuppressionIsNull(String email);

    /**
     * Trouve un patient par téléphone
     */
    Optional<Patient> findByTelephoneAndDateSuppressionIsNull(String telephone);

    // ===== VÉRIFICATIONS D'EXISTENCE =====

    /**
     * Vérifie si un patient existe avec ce numéro de sécurité sociale
     */
    boolean existsByNumeroSecuAndDateSuppressionIsNull(String numeroSecu);

    /**
     * Vérifie si un patient existe avec cet email (insensible à la casse)
     */
    boolean existsByEmailIgnoreCaseAndDateSuppressionIsNull(String email);

    /**
     * Vérifie si un patient existe avec ce téléphone
     */
    boolean existsByTelephoneAndDateSuppressionIsNull(String telephone);

    // ===== RECHERCHES PAR STATUT =====

    /**
     * Trouve tous les patients par statut
     */
    Page<Patient> findByStatutAndDateSuppressionIsNull(PatientStatus statut, Pageable pageable);

    /**
     * Trouve tous les patients actifs
     */
    List<Patient> findByStatutAndDateSuppressionIsNull(PatientStatus statut);

    // ===== RECHERCHES SPÉCIALISÉES (gardées pour compatibilité) =====

    /**
     * Recherche par nom et prénom (utilise les methods queries Spring Data)
     */
    List<Patient> findByNomContainingIgnoreCaseAndDateSuppressionIsNull(String nom);

    /**
     * Recherche par ville
     */
    List<Patient> findByVilleContainingIgnoreCaseAndDateSuppressionIsNull(String ville);

    /**
     * Recherche par date de naissance
     */
    List<Patient> findByDateNaissanceAndDateSuppressionIsNull(LocalDate dateNaissance);

    /**
     * Recherche par sexe
     */
    List<Patient> findBySexeAndDateSuppressionIsNull(GenderType sexe);

    /**
     * Recherche par région
     */
    List<Patient> findByRegionAndDateSuppressionIsNull(String region);

    /**
     * Recherche par département
     */
    List<Patient> findByDepartementAndDateSuppressionIsNull(String departement);

    // ===== RECHERCHES AVEC REQUÊTES PERSONNALISÉES (si nécessaire) =====

    /**
     * Recherche par proximité géographique
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

    // ===== RECHERCHES DE PATIENTS AVEC CONDITIONS SPÉCIALES =====

    /**
     * Trouve les patients avec notifications activées
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateSuppression IS NULL AND " +
            "p.statut = 'ACTIF' AND " +
            "(p.notificationsResultats = true OR p.notificationsRdv = true OR p.notificationsRappels = true)")
    List<Patient> findPatientsWithNotificationsEnabled();

    /**
     * Trouve les patients avec allergies
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.allergiesConnues IS NOT NULL AND " +
            "p.allergiesConnues != '' AND " +
            "p.dateSuppression IS NULL")
    List<Patient> findPatientsWithAllergies();

    /**
     * Trouve les patients avec antécédents médicaux
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.antecedentsMedicaux IS NOT NULL AND " +
            "p.antecedentsMedicaux != '' AND " +
            "p.dateSuppression IS NULL")
    List<Patient> findPatientsWithMedicalHistory();

    // ===== STATISTIQUES =====

    /**
     * Compte le nombre de patients par statut
     */
    @Query("SELECT p.statut, COUNT(p) FROM Patient p WHERE p.dateSuppression IS NULL GROUP BY p.statut")
    List<Object[]> countPatientsByStatus();

    /**
     * Compte le nombre de patients par sexe
     */
    @Query("SELECT p.sexe, COUNT(p) FROM Patient p WHERE p.dateSuppression IS NULL GROUP BY p.sexe")
    List<Object[]> countPatientsByGender();

    /**
     * Compte le nombre de patients par ville
     */
    @Query("SELECT p.ville, COUNT(p) FROM Patient p WHERE " +
            "p.dateSuppression IS NULL GROUP BY p.ville ORDER BY COUNT(p) DESC")
    List<Object[]> countPatientsByCity();

    /**
     * Compte le nombre total de patients actifs
     */
    @Query("SELECT COUNT(p) FROM Patient p WHERE p.dateSuppression IS NULL AND p.statut = 'ACTIF'")
    long countActivePatients();

    // ===== REQUÊTES DE MAINTENANCE =====

    /**
     * Trouve les patients récemment modifiés
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateModification > :dateLimit AND " +
            "p.dateSuppression IS NULL")
    List<Patient> findRecentlyModifiedPatients(@Param("dateLimit") LocalDateTime dateLimit);

    // NOTE: Plus besoin de findByMultipleCriteria complexe !
    // La recherche multicritères se fait maintenant avec les Specifications
}