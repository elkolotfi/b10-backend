package com.lims.patient.repository;

import com.lims.patient.entity.Ordonnance;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

/**
 * Repository pour les ordonnances
 */
@Repository
public interface OrdonnanceRepository extends JpaRepository<Ordonnance, UUID> {

    /**
     * Trouve toutes les ordonnances d'un patient
     */
    List<Ordonnance> findByPatientIdAndDateSuppressionIsNullOrderByDatePrescriptionDesc(UUID patientId);

    /**
     * Trouve les ordonnances actives d'un patient
     */
    @Query("SELECT o FROM Ordonnance o WHERE " +
            "o.patient.id = :patientId AND " +
            "o.statut IN ('EN_ATTENTE', 'VALIDEE') AND " +
            "o.dateSuppression IS NULL")
    List<Ordonnance> findActiveByPatientId(@Param("patientId") UUID patientId);

    /**
     * Compte les patients avec ordonnance active
     */
    @Query("SELECT COUNT(DISTINCT o.patient.id) FROM Ordonnance o WHERE " +
            "o.statut IN ('EN_ATTENTE', 'VALIDEE') AND " +
            "o.dateSuppression IS NULL AND " +
            "o.patient.dateSuppression IS NULL")
    long countPatientsWithActivePrescription();

    /**
     * Trouve les ordonnances renouvelables qui expirent bientôt
     */
    @Query("SELECT o FROM Ordonnance o WHERE " +
            "o.estRenouvelable = true AND " +
            "o.renouvelableJusqu BETWEEN CURRENT_DATE AND :dateLimit AND " +
            "o.dateSuppression IS NULL")
    List<Ordonnance> findRenewableExpiringBefore(@Param("dateLimit") LocalDate dateLimit);
}
