package com.lims.patient.repository;

import com.lims.patient.entity.PatientAssurance;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository pour les assurances
 */
@Repository
public interface PatientAssuranceRepository extends JpaRepository<PatientAssurance, UUID> {

    /**
     * Trouve toutes les assurances d'un patient
     */
    List<PatientAssurance> findByPatientIdOrderByDateDebutDescTypeAssuranceAsc(UUID patientId);

    /**
     * Trouve les assurances actives d'un patient
     */
    @Query("SELECT pa FROM PatientAssurance pa WHERE " +
            "pa.patient.id = :patientId AND " +
            "pa.estActive = true AND " +
            "(pa.dateFin IS NULL OR pa.dateFin >= CURRENT_DATE) AND " +
            "pa.patient.dateSuppression IS NULL")
    List<PatientAssurance> findActiveByPatientId(@Param("patientId") UUID patientId);

    /**
     * Trouve l'assurance primaire active d'un patient
     */
    @Query("SELECT pa FROM PatientAssurance pa WHERE " +
            "pa.patient.id = :patientId AND " +
            "pa.typeAssurance = 'PRIMAIRE' AND " +
            "pa.estActive = true AND " +
            "(pa.dateFin IS NULL OR pa.dateFin >= CURRENT_DATE)")
    Optional<PatientAssurance> findActivePrimaryInsurance(@Param("patientId") UUID patientId);

    /**
     * Compte les patients avec assurance active
     */
    @Query("SELECT COUNT(DISTINCT pa.patient.id) FROM PatientAssurance pa WHERE " +
            "pa.estActive = true AND " +
            "(pa.dateFin IS NULL OR pa.dateFin >= CURRENT_DATE) AND " +
            "pa.patient.dateSuppression IS NULL")
    long countPatientsWithActiveInsurance();
}
