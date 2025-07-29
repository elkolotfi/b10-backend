// lims-patient-service/src/main/java/com/lims/patient/repository/PatientAssuranceRepository.java
package com.lims.patient.repository;

import com.lims.patient.entity.Patient;
import com.lims.patient.entity.PatientAssurance;
import com.lims.patient.enums.InsuranceType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository pour les assurances patients.
 * Optimisé pour les requêtes métier courantes.
 */
@Repository
public interface PatientAssuranceRepository extends JpaRepository<PatientAssurance, UUID> {

    // ===============================================================
    // RECHERCHES DE BASE CRITIQUES
    // ===============================================================

    /**
     * Trouve une assurance par ID et patient ID.
     * Utilisé par: PatientInsuranceService.findInsuranceById()
     */
    Optional<PatientAssurance> findByIdAndPatientId(UUID id, UUID patientId);

    /**
     * Trouve toutes les assurances d'un patient triées par date de création DESC.
     * Utilisé par: PatientInsuranceService.getPatientInsurances()
     */
    List<PatientAssurance> findByPatientIdOrderByDateCreationDesc(UUID patientId);

    /**
     * Trouve les assurances actives d'un patient.
     * Utilisé par: PatientInsuranceService.getPatientInsurances()
     */
    List<PatientAssurance> findByPatientIdAndEstActiveTrue(UUID patientId);

    /**
     * Trouve les assurances actives et valides d'un patient (requête complexe).
     * Utilisé par: PatientInsuranceService.getActiveInsurances()
     */
    @Query("SELECT pa FROM PatientAssurance pa WHERE pa.patient.id = :patientId " +
            "AND pa.estActive = true " +
            "AND pa.dateDebut <= :currentDate " +
            "AND (pa.dateFin IS NULL OR pa.dateFin >= :currentDate)")
    List<PatientAssurance> findByPatientIdAndEstActiveTrueAndDateDebutLessThanEqualAndDateFinGreaterThanEqualOrDateFinIsNull(
            @Param("patientId") UUID patientId,
            @Param("currentDate") LocalDate currentDate1,
            @Param("currentDate") LocalDate currentDate2);

    // ===============================================================
    // VÉRIFICATIONS DE CONFLITS MÉTIER
    // ===============================================================

    /**
     * Vérifie si un patient a déjà une assurance active du même type.
     * Utilisé par: PatientInsuranceService.checkInsuranceConflicts()
     */
    boolean existsByPatientAndTypeAssuranceAndEstActiveTrue(Patient patient, InsuranceType typeAssurance);

    /**
     * Vérifie les conflits en excluant une assurance spécifique (pour les mises à jour).
     * Utilisé par: PatientInsuranceService.checkInsuranceConflicts()
     */
    boolean existsByPatientAndTypeAssuranceAndEstActiveTrueAndIdNot(
            Patient patient, InsuranceType typeAssurance, UUID excludeId);

    /**
     * Compte les assurances actives d'un patient par type.
     * Utile pour les validations métier.
     */
    @Query("SELECT COUNT(pa) FROM PatientAssurance pa WHERE pa.patient.id = :patientId " +
            "AND pa.typeAssurance = :typeAssurance AND pa.estActive = true")
    long countByPatientIdAndTypeAssuranceAndEstActiveTrue(
            @Param("patientId") UUID patientId,
            @Param("typeAssurance") InsuranceType typeAssurance);

    // ===============================================================
    // RECHERCHES PAR DOCUMENT
    // ===============================================================

    /**
     * Trouve les assurances par référence de document.
     * Utile pour éviter les doublons de documents.
     */
    List<PatientAssurance> findByReferenceDocument(String referenceDocument);

    /**
     * Vérifie si un document est déjà utilisé par une autre assurance.
     */
    boolean existsByReferenceDocumentAndIdNot(String referenceDocument, UUID excludeId);

    // ===============================================================
    // RECHERCHES PAR ORGANISME
    // ===============================================================

    /**
     * Trouve les assurances d'un patient pour un organisme donné.
     * Utile pour détecter les duplicatas.
     */
    List<PatientAssurance> findByPatientIdAndNomOrganismeIgnoreCase(UUID patientId, String nomOrganisme);

    /**
     * Trouve les assurances par numéro d'adhérent.
     * Utile pour détecter les duplicatas.
     */
    List<PatientAssurance> findByNumeroAdherent(String numeroAdherent);

    // ===============================================================
    // RECHERCHES PAR DATE
    // ===============================================================

    /**
     * Trouve les assurances qui expirent bientôt.
     * Utile pour les alertes.
     */
    @Query("SELECT pa FROM PatientAssurance pa WHERE pa.estActive = true " +
            "AND pa.dateFin IS NOT NULL " +
            "AND pa.dateFin BETWEEN :startDate AND :endDate")
    List<PatientAssurance> findExpiringInsurances(
            @Param("startDate") LocalDate startDate,
            @Param("endDate") LocalDate endDate);

    /**
     * Trouve les assurances expirées qui sont encore marquées comme actives.
     * Utile pour le nettoyage automatique.
     */
    @Query("SELECT pa FROM PatientAssurance pa WHERE pa.estActive = true " +
            "AND pa.dateFin IS NOT NULL " +
            "AND pa.dateFin < :currentDate")
    List<PatientAssurance> findExpiredActiveInsurances(@Param("currentDate") LocalDate currentDate);

    // ===============================================================
    // REQUÊTES DE STATISTIQUES
    // ===============================================================

    /**
     * Compte le nombre total d'assurances actives.
     */
    long countByEstActiveTrue();

    /**
     * Compte les assurances par type.
     */
    long countByTypeAssurance(InsuranceType typeAssurance);

    /**
     * Trouve les organismes les plus utilisés.
     */
    @Query("SELECT pa.nomOrganisme, COUNT(pa) as count FROM PatientAssurance pa " +
            "WHERE pa.estActive = true " +
            "GROUP BY pa.nomOrganisme " +
            "ORDER BY count DESC")
    List<Object[]> findMostUsedOrganismes();

    // ===============================================================
    // REQUÊTES POUR AUDIT ET CONTRÔLE
    // ===============================================================

    /**
     * Trouve les assurances sans document (ne devrait plus arriver après la contrainte).
     */
    @Query("SELECT pa FROM PatientAssurance pa WHERE pa.referenceDocument IS NULL OR pa.referenceDocument = ''")
    List<PatientAssurance> findInsurancesWithoutDocument();

    /**
     * Trouve les assurances modifiées récemment.
     */
    @Query("SELECT pa FROM PatientAssurance pa WHERE pa.dateModification >= :since")
    List<PatientAssurance> findRecentlyModified(@Param("since") java.time.LocalDateTime since);
}