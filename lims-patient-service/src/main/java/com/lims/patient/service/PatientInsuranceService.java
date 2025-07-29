package com.lims.patient.service;

import com.lims.patient.dto.request.InsuranceRequest;
import com.lims.patient.dto.response.PatientInsuranceResponse;
import com.lims.patient.entity.Patient;
import com.lims.patient.entity.PatientAssurance;
import com.lims.patient.enums.InsuranceType;
import com.lims.patient.exception.InsuranceConflictException;
import com.lims.patient.exception.InsuranceNotFoundException;
import com.lims.patient.exception.InvalidInsuranceDataException;
import com.lims.patient.exception.PatientNotFoundException;
import com.lims.patient.mapper.PatientInsuranceMapper;
import com.lims.patient.repository.PatientAssuranceRepository;
import com.lims.patient.repository.PatientRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Service de gestion des assurances/mutuelles des patients.
 * Implémente la règle métier : document justificatif OBLIGATOIRE.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class PatientInsuranceService {

    private final PatientRepository patientRepository;
    private final PatientAssuranceRepository assuranceRepository;
    private final PatientInsuranceMapper insuranceMapper;

    /**
     * Ajoute une nouvelle assurance à un patient.
     * RÈGLE MÉTIER : Le document justificatif est OBLIGATOIRE.
     */
    public PatientInsuranceResponse addInsurance(UUID patientId, InsuranceRequest request, String createdBy) {
        log.info("Ajout d'une assurance {} pour le patient {}", request.typeAssurance(), patientId);

        // 1. Validation du document obligatoire
        validateDocumentRequired(request.referenceDocument());

        // 2. Récupération du patient
        Patient patient = findPatientById(patientId);

        // 3. Validation métier
        validateInsuranceRequest(request, patient);

        // 4. Vérification des conflits (même type actif)
        checkInsuranceConflicts(patient, request.typeAssurance());

        // 5. Création de l'assurance
        PatientAssurance assurance = buildAssuranceFromRequest(request, patient);

        // 6. Sauvegarde
        PatientAssurance savedAssurance = assuranceRepository.save(assurance);

        log.info("Assurance {} créée avec succès pour le patient {}", savedAssurance.getId(), patientId);
        return insuranceMapper.toResponse(savedAssurance);
    }

    /**
     * Récupère les assurances d'un patient.
     */
    @Transactional(readOnly = true)
    public List<PatientInsuranceResponse> getPatientInsurances(UUID patientId, boolean includeInactive) {
        log.debug("Récupération des assurances pour le patient {} (includeInactive: {})", patientId, includeInactive);

        // Vérification que le patient existe
        findPatientById(patientId);

        List<PatientAssurance> assurances = includeInactive
                ? assuranceRepository.findByPatientIdOrderByDateCreationDesc(patientId)
                : assuranceRepository.findByPatientIdAndEstActiveTrue(patientId);

        return assurances.stream()
                .map(insuranceMapper::toResponse)
                .toList();
    }

    /**
     * Récupère une assurance spécifique.
     */
    @Transactional(readOnly = true)
    public PatientInsuranceResponse getInsuranceById(UUID patientId, UUID insuranceId) {
        log.debug("Récupération de l'assurance {} pour le patient {}", insuranceId, patientId);

        PatientAssurance assurance = findInsuranceById(patientId, insuranceId);
        return insuranceMapper.toResponse(assurance);
    }

    /**
     * Met à jour une assurance existante.
     */
    public PatientInsuranceResponse updateInsurance(UUID patientId, UUID insuranceId,
                                                    InsuranceRequest request, String updatedBy) {
        log.info("Mise à jour de l'assurance {} pour le patient {}", insuranceId, patientId);

        // 1. Validation du document obligatoire
        validateDocumentRequired(request.referenceDocument());

        // 2. Récupération de l'assurance
        PatientAssurance existingAssurance = findInsuranceById(patientId, insuranceId);

        // 3. Validation métier
        validateInsuranceRequest(request, existingAssurance.getPatient());

        // 4. Si changement de type, vérifier les conflits
        if (!existingAssurance.getTypeAssurance().equals(request.typeAssurance())) {
            checkInsuranceConflicts(existingAssurance.getPatient(), request.typeAssurance(), insuranceId);
        }

        // 5. Mise à jour des champs
        updateAssuranceFields(existingAssurance, request);
        existingAssurance.setDateModification(LocalDateTime.now());

        // 6. Sauvegarde
        PatientAssurance savedAssurance = assuranceRepository.save(existingAssurance);

        log.info("Assurance {} mise à jour avec succès", insuranceId);
        return insuranceMapper.toResponse(savedAssurance);
    }

    /**
     * Active ou désactive une assurance.
     */
    public PatientInsuranceResponse updateInsuranceStatus(UUID patientId, UUID insuranceId,
                                                          boolean active, String updatedBy) {
        log.info("Modification du statut de l'assurance {} à {}", insuranceId, active);

        PatientAssurance assurance = findInsuranceById(patientId, insuranceId);
        assurance.setEstActive(active);
        assurance.setDateModification(LocalDateTime.now());

        PatientAssurance savedAssurance = assuranceRepository.save(assurance);
        return insuranceMapper.toResponse(savedAssurance);
    }

    /**
     * Supprime définitivement une assurance.
     */
    public void deleteInsurance(UUID patientId, UUID insuranceId, String reason, String deletedBy) {
        log.warn("Suppression définitive de l'assurance {} - Motif: {}", insuranceId, reason);

        PatientAssurance assurance = findInsuranceById(patientId, insuranceId);

        // TODO: Vérifier si l'assurance n'est pas utilisée dans des prélèvements en cours
        // if (assuranceInUse(insuranceId)) {
        //     throw new InsuranceInUseException("Impossible de supprimer une assurance en cours d'utilisation");
        // }

        assuranceRepository.delete(assurance);
        log.info("Assurance {} supprimée définitivement", insuranceId);
    }

    /**
     * Récupère uniquement les assurances actives d'un patient.
     */
    @Transactional(readOnly = true)
    public List<PatientInsuranceResponse> getActiveInsurances(UUID patientId) {
        log.debug("Récupération des assurances actives pour le patient {}", patientId);

        findPatientById(patientId); // Vérification existence patient

        List<PatientAssurance> activeAssurances = assuranceRepository
                .findByPatientIdAndEstActiveTrueAndDateDebutLessThanEqualAndDateFinGreaterThanEqualOrDateFinIsNull(
                        patientId, LocalDate.now(), LocalDate.now());

        return activeAssurances.stream()
                .map(insuranceMapper::toResponse)
                .toList();
    }

    /**
     * Valide le document d'une assurance.
     */
    public PatientInsuranceResponse validateInsuranceDocument(UUID patientId, UUID insuranceId,
                                                              String validationComment, String validatedBy) {
        log.info("Validation du document de l'assurance {} par {}", insuranceId, validatedBy);

        PatientAssurance assurance = findInsuranceById(patientId, insuranceId);

        // TODO: Ajouter champs validation dans l'entité
        // assurance.setDocumentValidated(true);
        // assurance.setValidatedBy(validatedBy);
        // assurance.setValidationDate(LocalDateTime.now());
        // assurance.setValidationComment(validationComment);

        assurance.setDateModification(LocalDateTime.now());
        PatientAssurance savedAssurance = assuranceRepository.save(assurance);

        return insuranceMapper.toResponse(savedAssurance);
    }

    // ====================================================================
    // MÉTHODES PRIVÉES DE VALIDATION ET UTILITAIRES
    // ====================================================================

    /**
     * Validation OBLIGATOIRE du document justificatif.
     * RÈGLE MÉTIER CRITIQUE : Pas de document = Pas d'assurance.
     */
    private void validateDocumentRequired(String referenceDocument) {
        if (!StringUtils.hasText(referenceDocument)) {
            throw new InvalidInsuranceDataException(
                    "Le document justificatif est obligatoire pour créer ou modifier une assurance. " +
                            "Veuillez scanner ou uploader la carte de mutuelle du patient."
            );
        }
    }

    /**
     * Récupère un patient par son ID avec vérification d'existence.
     */
    private Patient findPatientById(UUID patientId) {
        return patientRepository.findByIdAndDateSuppressionIsNull(patientId)
                .orElseThrow(() -> new PatientNotFoundException("Patient non trouvé: " + patientId));
    }

    /**
     * Récupère une assurance par son ID avec vérification d'appartenance au patient.
     */
    private PatientAssurance findInsuranceById(UUID patientId, UUID insuranceId) {
        return assuranceRepository.findByIdAndPatientId(insuranceId, patientId)
                .orElseThrow(() -> new InsuranceNotFoundException(
                        "Assurance non trouvée: " + insuranceId + " pour le patient: " + patientId));
    }

    /**
     * Valide les données de la demande d'assurance.
     */
    private void validateInsuranceRequest(InsuranceRequest request, Patient patient) {
        // Validation des dates
        if (request.dateFin() != null && request.dateFin().isBefore(request.dateDebut())) {
            throw new InvalidInsuranceDataException("La date de fin ne peut pas être antérieure à la date de début");
        }

        // Validation du pourcentage
        if (request.pourcentagePriseCharge() != null) {
            if (request.pourcentagePriseCharge().compareTo(java.math.BigDecimal.ZERO) < 0 ||
                    request.pourcentagePriseCharge().compareTo(java.math.BigDecimal.valueOf(100)) > 0) {
                throw new InvalidInsuranceDataException("Le pourcentage de prise en charge doit être entre 0 et 100");
            }
        }

        // Validation du numéro d'adhérent (longueur minimale)
        if (request.numeroAdherent().length() < 5) {
            throw new InvalidInsuranceDataException("Le numéro d'adhérent doit contenir au moins 5 caractères");
        }
    }

    /**
     * Vérifie les conflits d'assurance (même type actif).
     */
    private void checkInsuranceConflicts(Patient patient, InsuranceType typeAssurance) {
        checkInsuranceConflicts(patient, typeAssurance, null);
    }

    private void checkInsuranceConflicts(Patient patient, InsuranceType typeAssurance, UUID excludeId) {
        boolean hasConflict = assuranceRepository.existsByPatientAndTypeAssuranceAndEstActiveTrueAndIdNot(
                patient, typeAssurance, excludeId != null ? excludeId : UUID.randomUUID());

        if (hasConflict) {
            throw new InsuranceConflictException(
                    "Le patient possède déjà une assurance active de type: " + typeAssurance.getLabel());
        }
    }

    /**
     * Construit une entité PatientAssurance à partir de la requête.
     */
    private PatientAssurance buildAssuranceFromRequest(InsuranceRequest request, Patient patient) {
        return PatientAssurance.builder()
                .patient(patient)
                .typeAssurance(request.typeAssurance())
                .nomOrganisme(request.nomOrganisme())
                .numeroAdherent(request.numeroAdherent())
                .dateDebut(request.dateDebut())
                .dateFin(request.dateFin())
                .tiersPayantAutorise(request.tiersPayantAutorise() != null ? request.tiersPayantAutorise() : false)
                .pourcentagePriseCharge(request.pourcentagePriseCharge())
                .referenceDocument(request.referenceDocument()) // OBLIGATOIRE
                .dateUploadDocument(LocalDateTime.now())
                .estActive(true)
                .dateCreation(LocalDateTime.now())
                .build();
    }

    /**
     * Met à jour les champs d'une assurance existante.
     */
    private void updateAssuranceFields(PatientAssurance assurance, InsuranceRequest request) {
        assurance.setTypeAssurance(request.typeAssurance());
        assurance.setNomOrganisme(request.nomOrganisme());
        assurance.setNumeroAdherent(request.numeroAdherent());
        assurance.setDateDebut(request.dateDebut());
        assurance.setDateFin(request.dateFin());
        assurance.setTiersPayantAutorise(request.tiersPayantAutorise() != null ? request.tiersPayantAutorise() : false);
        assurance.setPourcentagePriseCharge(request.pourcentagePriseCharge());

        // Si nouveau document, mettre à jour la référence et la date
        if (!request.referenceDocument().equals(assurance.getReferenceDocument())) {
            assurance.setReferenceDocument(request.referenceDocument());
            assurance.setDateUploadDocument(LocalDateTime.now());
        }
    }
}