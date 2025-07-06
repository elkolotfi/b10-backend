package com.lims.patient.repository;


import com.lims.patient.entity.Patient;
import com.lims.patient.entity.PatientEmail;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository pour les emails
 */
@Repository
public interface PatientEmailRepository extends JpaRepository<PatientEmail, UUID> {

    /**
     * Trouve tous les emails d'un patient
     */
    List<PatientEmail> findByPatientIdOrderByEstPrincipalDescDateCreationAsc(UUID patientId);

    /**
     * Trouve l'email principal d'un patient
     */
    Optional<PatientEmail> findByPatientIdAndEstPrincipalTrue(UUID patientId);

    /**
     * Recherche par adresse email
     */
    Optional<PatientEmail> findByAdresseEmailAndPatientDateSuppressionIsNull(String adresseEmail);

    /**
     * Vérifie l'existence d'un email pour un patient
     */
    boolean existsByPatientIdAndAdresseEmail(UUID patientId, String adresseEmail);

    /**
     * Supprime tous les emails d'un patient
     */
    void deleteByPatient(Patient patient);

    /**
     * Trouve les emails avec notifications activées
     */
    @Query("SELECT pe FROM PatientEmail pe WHERE " +
            "pe.patient.dateSuppression IS NULL AND " +
            "(pe.notificationsResultats = true OR pe.notificationsRdv = true OR pe.notificationsRappels = true)")
    List<PatientEmail> findEmailsWithNotificationsEnabled();
}
