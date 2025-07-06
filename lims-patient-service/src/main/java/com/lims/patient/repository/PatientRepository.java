package com.lims.patient.repository;

import com.lims.patient.entity.Patient;
import com.lims.patient.enums.PatientStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PatientRepository extends JpaRepository<Patient, UUID> {

    // ===== RECHERCHES DE BASE =====

    /**
     * Trouve un patient par ID excluant les supprimés
     */
    Optional<Patient> findByIdAndDateSuppressionIsNull(UUID id);

    /**
     * Trouve un patient par NIR excluant les supprimés
     */
    Optional<Patient> findByNumeroSecuAndDateSuppressionIsNull(String numeroSecu);

    /**
     * Vérifie l'existence d'un patient par NIR excluant les supprimés
     */
    boolean existsByNumeroSecuAndDateSuppressionIsNull(String numeroSecu);

    // ===== RECHERCHES PAR CRITÈRES =====

    /**
     * Recherche par nom et prénom (insensible à la casse)
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "LOWER(p.nom) LIKE LOWER(CONCAT('%', :nom, '%')) AND " +
            "LOWER(p.prenom) LIKE LOWER(CONCAT('%', :prenom, '%')) AND " +
            "p.dateSuppression IS NULL")
    List<Patient> findByNomAndPrenomContainingIgnoreCase(
            @Param("nom") String nom,
            @Param("prenom") String prenom);

    /**
     * Recherche par fragment de NIR (pour les 3-4 derniers chiffres)
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.numeroSecu LIKE CONCAT('%', :fragment) AND " +
            "p.dateSuppression IS NULL")
    List<Patient> findByNumeroSecuEndingWith(@Param("fragment") String fragment);

    /**
     * Recherche par date de naissance
     */
    List<Patient> findByDateNaissanceAndDateSuppressionIsNull(LocalDate dateNaissance);

    /**
     * Recherche par tranche d'âge
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateNaissance BETWEEN :dateNaissanceDebut AND :dateNaissanceFin AND " +
            "p.dateSuppression IS NULL")
    List<Patient> findByDateNaissanceBetween(
            @Param("dateNaissanceDebut") LocalDate dateNaissanceDebut,
            @Param("dateNaissanceFin") LocalDate dateNaissanceFin);

    // ===== STATISTIQUES =====

    /**
     * Compte les patients actifs (non supprimés)
     */
    long countByDateSuppressionIsNull();

    /**
     * Compte les patients par statut
     */
    long countByStatutAndDateSuppressionIsNull(PatientStatus statut);

    /**
     * Compte les nouveaux patients depuis une date
     */
    long countByDateCreationGreaterThanEqualAndDateSuppressionIsNull(LocalDateTime dateDebut);

    /**
     * Trouve les patients créés par un utilisateur spécifique
     */
    List<Patient> findByCreePar(String creePar);

    // ===== RECHERCHES AVANCÉES =====

    /**
     * Recherche de patients avec assurance active
     */
    @Query("SELECT DISTINCT p FROM Patient p " +
            "JOIN p.assurances a WHERE " +
            "a.estActive = true AND " +
            "(a.dateFin IS NULL OR a.dateFin >= CURRENT_DATE) AND " +
            "p.dateSuppression IS NULL")
    List<Patient> findPatientsWithActiveInsurance();

    /**
     * Recherche de patients avec ordonnance en cours
     */
    @Query("SELECT DISTINCT p FROM Patient p " +
            "JOIN p.ordonnances o WHERE " +
            "o.statut IN ('EN_ATTENTE', 'VALIDEE') AND " +
            "o.dateSuppression IS NULL AND " +
            "p.dateSuppression IS NULL")
    List<Patient> findPatientsWithActivePrescription();

    /**
     * Recherche paginée de tous les patients actifs
     */
    Page<Patient> findByDateSuppressionIsNullOrderByNomAsc(Pageable pageable);
}
