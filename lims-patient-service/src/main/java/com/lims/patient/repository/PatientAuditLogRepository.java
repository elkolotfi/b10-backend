package com.lims.patient.repository;

import com.lims.patient.entity.PatientAuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Repository pour l'audit des patients
 */
@Repository
public interface PatientAuditLogRepository extends JpaRepository<PatientAuditLog, Long> {

    /**
     * Trouve les logs d'audit d'un patient
     */
    List<PatientAuditLog> findByPatientIdOrderByDateActionDesc(UUID patientId);

    /**
     * Trouve les logs d'audit par utilisateur
     */
    List<PatientAuditLog> findByPerformedByOrderByDateActionDesc(String performedBy);

    /**
     * Trouve les logs d'audit par action
     */
    List<PatientAuditLog> findByActionOrderByDateActionDesc(String action);

    /**
     * Trouve les logs d'audit récents
     */
    @Query("SELECT pal FROM PatientAuditLog pal WHERE " +
            "pal.dateAction >= :dateDebut " +
            "ORDER BY pal.dateAction DESC")
    List<PatientAuditLog> findRecentLogs(@Param("dateDebut") LocalDateTime dateDebut);

    /**
     * Supprime les logs d'audit anciens (RGPD - conservation limitée)
     */
    @Query("DELETE FROM PatientAuditLog pal WHERE pal.dateAction < :dateLimit")
    void deleteOldLogs(@Param("dateLimit") LocalDateTime dateLimit);
}
