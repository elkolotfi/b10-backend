package com.lims.patient.repository;

import com.lims.patient.entity.Patient;
import com.lims.patient.entity.PatientAddress;
import com.lims.patient.enums.AddressType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository pour les adresses
 */
@Repository
public interface PatientAddressRepository extends JpaRepository<PatientAddress, UUID> {

    /**
     * Trouve toutes les adresses d'un patient
     */
    List<PatientAddress> findByPatientIdOrderByEstPrincipaleDescDateCreationAsc(UUID patientId);

    /**
     * Trouve l'adresse principale d'un patient par type
     */
    Optional<PatientAddress> findByPatientIdAndTypeAdresseAndEstPrincipaleTrue(
            UUID patientId, AddressType typeAdresse);

    /**
     * Recherche par ville
     */
    @Query("SELECT pa FROM PatientAddress pa WHERE " +
            "LOWER(pa.ville) LIKE LOWER(CONCAT('%', :ville, '%')) AND " +
            "pa.patient.dateSuppression IS NULL")
    List<PatientAddress> findByVilleContainingIgnoreCase(@Param("ville") String ville);

    /**
     * Recherche par code postal
     */
    @Query("SELECT pa FROM PatientAddress pa WHERE " +
            "pa.codePostal = :codePostal AND " +
            "pa.patient.dateSuppression IS NULL")
    List<PatientAddress> findByCodePostal(@Param("codePostal") String codePostal);

    /**
     * Supprime toutes les adresses d'un patient
     */
    void deleteByPatient(Patient patient);

    /**
     * Compte les adresses par ville
     */
    @Query("SELECT pa.ville, COUNT(pa) FROM PatientAddress pa " +
            "WHERE pa.patient.dateSuppression IS NULL " +
            "GROUP BY pa.ville ORDER BY COUNT(pa) DESC")
    List<Object[]> countByVille();
}