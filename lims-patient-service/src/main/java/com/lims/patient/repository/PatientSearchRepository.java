package com.lims.patient.repository;

import com.lims.patient.dto.request.PatientSearchRequest;
import com.lims.patient.entity.Patient;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

/**
 * Interface pour les recherches complexes de patients
 */
public interface PatientSearchRepository {

    /**
     * Recherche avancée de patients avec critères multiples
     */
    Page<Patient> searchPatients(PatientSearchRequest request, Pageable pageable);

    /**
     * Trouve un patient par numéro de téléphone
     */
    Optional<Patient> findPatientByPhone(String phoneNumber);

    /**
     * Compte les patients avec assurance active
     */
    long countPatientsWithActiveInsurance();

    /**
     * Compte les patients avec ordonnance active
     */
    long countPatientsWithActivePrescription();

    /**
     * Recherche de doublons potentiels
     */
    List<Patient> findPotentialDuplicates(String nom, String prenom, LocalDate dateNaissance);
}