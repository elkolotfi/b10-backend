package com.lims.patient.repository;

import com.lims.patient.entity.Patient;
import com.lims.patient.entity.PatientContact;
import com.lims.patient.enums.ContactType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository pour les contacts téléphoniques
 */
@Repository
public interface PatientContactRepository extends JpaRepository<PatientContact, UUID> {

    /**
     * Trouve tous les contacts d'un patient
     */
    List<PatientContact> findByPatientIdOrderByEstPrincipalDescDateCreationAsc(UUID patientId);

    /**
     * Trouve le contact principal d'un patient par type
     */
    Optional<PatientContact> findByPatientIdAndTypeContactAndEstPrincipalTrue(
            UUID patientId, ContactType typeContact);

    /**
     * Recherche par numéro de téléphone
     */
    @Query("SELECT pc FROM PatientContact pc WHERE " +
            "pc.numeroTelephone = :numero AND " +
            "pc.patient.dateSuppression IS NULL")
    List<PatientContact> findByNumeroTelephone(@Param("numero") String numero);

    /**
     * Supprime tous les contacts d'un patient
     */
    void deleteByPatient(Patient patient);

    /**
     * Vérifie l'existence d'un contact principal pour un type donné
     */
    boolean existsByPatientIdAndTypeContactAndEstPrincipalTrue(UUID patientId, ContactType typeContact);
}
