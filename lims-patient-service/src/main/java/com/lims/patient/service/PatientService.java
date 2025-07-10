package com.lims.patient.service;

import com.lims.patient.dto.request.*;
import com.lims.patient.dto.response.*;
import com.lims.patient.entity.Patient;
import com.lims.patient.entity.PatientAssurance;
import com.lims.patient.enums.PatientStatus;
import com.lims.patient.exception.DuplicatePatientException;
import com.lims.patient.exception.InvalidPatientDataException;
import com.lims.patient.exception.PatientNotFoundException;
import com.lims.patient.repository.PatientRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service principal pour la gestion des patients - Version centralisée
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class PatientService {

    private final PatientRepository patientRepository;
    private final PatientSearchService patientSearchService;

    /**
     * Crée un nouveau patient avec structure centralisée
     */
    public PatientResponse createPatient(CreatePatientRequest request) {
        log.info("Création d'un nouveau patient: {} {}",
                request.personalInfo().prenom(), request.personalInfo().nom());

        // 1. Validation des données
        validateCreateRequest(request);

        // 2. Vérification des doublons
        checkForDuplicates(request);

        // 3. Construction de l'entité Patient
        Patient patient = buildPatientFromRequest(request);

        // 4. Ajout des assurances
        if (request.insurances() != null) {
            for (InsuranceRequest insuranceRequest : request.insurances()) {
                PatientAssurance assurance = buildAssuranceFromRequest(insuranceRequest);
                patient.addAssurance(assurance);
            }
        }

        // 5. Sauvegarde
        patient = patientRepository.save(patient);

        log.info("Patient créé avec succès: ID={}", patient.getId());
        return mapToResponse(patient);
    }

    /**
     * Met à jour un patient existant
     */
    public PatientResponse updatePatient(UUID patientId, UpdatePatientRequest request) {
        log.info("Mise à jour du patient: {}", patientId);

        Patient patient = getPatientById(patientId);

        // Validation de la mise à jour
        validateUpdateRequest(request, patient);

        // Mise à jour des informations personnelles
        if (request.personalInfo() != null) {
            updatePersonalInfo(patient, request.personalInfo());
        }

        // Mise à jour des informations de contact
        if (request.contactInfo() != null) {
            updateContactInfo(patient, request.contactInfo());
        }

        // Mise à jour des consentements
        if (request.consent() != null) {
            updateConsent(patient, request.consent());
        }

        // Mise à jour des assurances
        if (request.insurances() != null) {
            updateInsurances(patient, request.insurances());
        }

        patient = patientRepository.save(patient);
        log.info("Patient mis à jour avec succès: {}", patientId);

        return mapToResponse(patient);
    }

    /**
     * Recherche un patient par ID
     */
    @Transactional(readOnly = true)
    public PatientResponse getPatient(UUID patientId) {
        Patient patient = getPatientById(patientId);
        return mapToResponse(patient);
    }

    /**
     * Suppression logique d'un patient
     */
    public void deletePatient(UUID patientId) {
        log.info("Suppression du patient: {}", patientId);

        Patient patient = getPatientById(patientId);
        patient.setStatut(PatientStatus.INACTIF);
        patient.setDateSuppression(LocalDateTime.now());

        patientRepository.save(patient);
        log.info("Patient supprimé avec succès: {}", patientId);
    }

    /**
     * Recherche de patients avec critères multiples
     */
    @Transactional(readOnly = true)
    public PatientSearchResponse searchPatients(PatientSearchRequest request) {
        log.info("Recherche de patients avec les critères: {}", request);
        return patientSearchService.searchPatients(request);
    }

    /**
     * Recherche par email
     */
    @Transactional(readOnly = true)
    public Optional<PatientResponse> findByEmail(String email) {
        return patientRepository.findByEmailIgnoreCaseAndDateSuppressionIsNull(email)
                .map(this::mapToResponse);
    }

    /**
     * Recherche par téléphone
     */
    @Transactional(readOnly = true)
    public Optional<PatientResponse> findByTelephone(String telephone) {
        return patientRepository.findByTelephoneAndDateSuppressionIsNull(telephone)
                .map(this::mapToResponse);
    }

    /**
     * Recherche par numéro de sécurité sociale
     */
    @Transactional(readOnly = true)
    public Optional<PatientResponse> findByNumeroSecu(String numeroSecu) {
        return patientRepository.findByNumeroSecuAndDateSuppressionIsNull(numeroSecu)
                .map(this::mapToResponse);
    }

    /**
     * Obtient tous les patients actifs
     */
    @Transactional(readOnly = true)
    public List<PatientSummaryResponse> getActivePatients(int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("dateCreation").descending());
        Page<Patient> patients = patientRepository.findByStatutAndDateSuppressionIsNull(
                PatientStatus.ACTIF, pageable);

        return patients.stream()
                .map(this::mapToSummaryResponse)
                .collect(Collectors.toList());
    }

    // ============================================
    // MÉTHODES PRIVÉES
    // ============================================

    /**
     * Récupère un patient par ID ou lance une exception
     */
    private Patient getPatientById(UUID patientId) {
        return patientRepository.findByIdAndDateSuppressionIsNull(patientId)
                .orElseThrow(() -> new PatientNotFoundException("Patient non trouvé: " + patientId));
    }

    /**
     * Validation de la requête de création
     */
    private void validateCreateRequest(CreatePatientRequest request) {
        if (request == null) {
            throw new InvalidPatientDataException("La requête de création ne peut pas être nulle");
        }

        if (request.personalInfo() == null) {
            throw new InvalidPatientDataException("Les informations personnelles sont obligatoires");
        }

        if (request.contactInfo() == null) {
            throw new InvalidPatientDataException("Les informations de contact sont obligatoires");
        }

        if (request.consent() == null) {
            throw new InvalidPatientDataException("Les consentements sont obligatoires");
        }

        // Validation du consentement obligatoire
        if (!request.consent().consentementCreationCompte()) {
            throw new InvalidPatientDataException("Le consentement de création de compte est obligatoire");
        }
    }

    /**
     * Validation de la requête de mise à jour
     */
    private void validateUpdateRequest(UpdatePatientRequest request, Patient patient) {
        if (request == null) {
            throw new InvalidPatientDataException("La requête de mise à jour ne peut pas être nulle");
        }

        // Validation que le patient peut être modifié
        if (patient.getStatut() == PatientStatus.DECEDE) {
            throw new InvalidPatientDataException("Impossible de modifier un patient décédé");
        }
    }

    /**
     * Vérification des doublons
     */
    private void checkForDuplicates(CreatePatientRequest request) {
        // Vérification par numéro de sécurité sociale
        if (patientRepository.existsByNumeroSecuAndDateSuppressionIsNull(
                request.personalInfo().numeroSecu())) {
            throw new DuplicatePatientException("Un patient avec ce numéro de sécurité sociale existe déjà");
        }

        // Vérification par email
        if (patientRepository.existsByEmailIgnoreCaseAndDateSuppressionIsNull(
                request.contactInfo().email())) {
            throw new DuplicatePatientException("Un patient avec cet email existe déjà");
        }

        // Vérification par téléphone
        if (patientRepository.existsByTelephoneAndDateSuppressionIsNull(
                request.contactInfo().telephone())) {
            throw new DuplicatePatientException("Un patient avec ce téléphone existe déjà");
        }
    }

    /**
     * Construction de l'entité Patient depuis la requête
     */
    private Patient buildPatientFromRequest(CreatePatientRequest request) {
        PersonalInfoRequest personalInfo = request.personalInfo();
        ContactInfoRequest contactInfo = request.contactInfo();
        ConsentRequest consent = request.consent();

        return Patient.builder()
                // Informations personnelles
                .nom(personalInfo.nom())
                .prenom(personalInfo.prenom())
                .nomJeuneFille(personalInfo.nomJeuneFille())
                .dateNaissance(personalInfo.dateNaissance())
                .lieuNaissance(personalInfo.lieuNaissance())
                .sexe(personalInfo.sexe())
                .numeroSecu(personalInfo.numeroSecu())
                .medecinTraitant(personalInfo.medecinTraitant())
                .allergiesConnues(personalInfo.allergiesConnues())
                .antecedentsMedicaux(personalInfo.antecedentsMedicaux())

                // Informations de contact centralisées
                .email(contactInfo.email())
                .telephone(contactInfo.telephone())
                .adresseLigne1(contactInfo.adresseLigne1())
                .adresseLigne2(contactInfo.adresseLigne2())
                .codePostal(contactInfo.codePostal())
                .ville(contactInfo.ville())
                .departement(contactInfo.departement())
                .region(contactInfo.region())
                .pays(contactInfo.pays() != null ? contactInfo.pays() : "France")
                .latitude(contactInfo.latitude())
                .longitude(contactInfo.longitude())

                // Préférences de communication
                .methodeLivraisonPreferee(contactInfo.methodeLivraisonPreferee())
                .preferenceNotification(contactInfo.preferenceNotification())
                .languePreferee(contactInfo.languePreferee() != null ? contactInfo.languePreferee() : "fr-FR")
                .notificationsResultats(contactInfo.notificationsResultats() != null ? contactInfo.notificationsResultats() : true)
                .notificationsRdv(contactInfo.notificationsRdv() != null ? contactInfo.notificationsRdv() : true)
                .notificationsRappels(contactInfo.notificationsRappels() != null ? contactInfo.notificationsRappels() : true)

                // Consentements RGPD
                .consentementCreationCompte(consent.consentementCreationCompte())
                .consentementSms(consent.consentementSms())
                .consentementEmail(consent.consentementEmail())
                .dateConsentement(consent.consentementCreationCompte() ? LocalDateTime.now() : null)

                // Métadonnées
                .statut(PatientStatus.ACTIF)
                .creePar(request.createdBy())
                .build();
    }

    /**
     * Construction d'une assurance depuis la requête
     */
    private PatientAssurance buildAssuranceFromRequest(InsuranceRequest request) {
        return PatientAssurance.builder()
                .typeAssurance(request.typeAssurance())
                .nomOrganisme(request.nomOrganisme())
                .numeroAdherent(request.numeroAdherent())
                .dateDebut(request.dateDebut())
                .dateFin(request.dateFin())
                .tiersPayantAutorise(request.tiersPayantAutorise() != null ? request.tiersPayantAutorise() : false)
                .pourcentagePriseCharge(request.pourcentagePriseCharge())
                .referenceDocument(request.referenceDocument())
                .estActive(true)
                .build();
    }

    /**
     * Met à jour les informations personnelles
     */
    private void updatePersonalInfo(Patient patient, PersonalInfoUpdateRequest personalInfo) {
        if (personalInfo.nom() != null) patient.setNom(personalInfo.nom());
        if (personalInfo.prenom() != null) patient.setPrenom(personalInfo.prenom());
        if (personalInfo.nomJeuneFille() != null) patient.setNomJeuneFille(personalInfo.nomJeuneFille());
        if (personalInfo.dateNaissance() != null) patient.setDateNaissance(personalInfo.dateNaissance());
        if (personalInfo.lieuNaissance() != null) patient.setLieuNaissance(personalInfo.lieuNaissance());
        if (personalInfo.sexe() != null) patient.setSexe(personalInfo.sexe());
        if (personalInfo.medecinTraitant() != null) patient.setMedecinTraitant(personalInfo.medecinTraitant());
        if (personalInfo.allergiesConnues() != null) patient.setAllergiesConnues(personalInfo.allergiesConnues());
        if (personalInfo.antecedentsMedicaux() != null) patient.setAntecedentsMedicaux(personalInfo.antecedentsMedicaux());
    }

    /**
     * Met à jour les informations de contact
     */
    private void updateContactInfo(Patient patient, ContactInfoUpdateRequest contactInfo) {
        if (contactInfo.email() != null) patient.setEmail(contactInfo.email());
        if (contactInfo.telephone() != null) patient.setTelephone(contactInfo.telephone());
        if (contactInfo.adresseLigne1() != null) patient.setAdresseLigne1(contactInfo.adresseLigne1());
        if (contactInfo.adresseLigne2() != null) patient.setAdresseLigne2(contactInfo.adresseLigne2());
        if (contactInfo.codePostal() != null) patient.setCodePostal(contactInfo.codePostal());
        if (contactInfo.ville() != null) patient.setVille(contactInfo.ville());
        if (contactInfo.departement() != null) patient.setDepartement(contactInfo.departement());
        if (contactInfo.region() != null) patient.setRegion(contactInfo.region());
        if (contactInfo.pays() != null) patient.setPays(contactInfo.pays());
        if (contactInfo.latitude() != null) patient.setLatitude(contactInfo.latitude());
        if (contactInfo.longitude() != null) patient.setLongitude(contactInfo.longitude());
        if (contactInfo.methodeLivraisonPreferee() != null) patient.setMethodeLivraisonPreferee(contactInfo.methodeLivraisonPreferee());
        if (contactInfo.preferenceNotification() != null) patient.setPreferenceNotification(contactInfo.preferenceNotification());
        if (contactInfo.languePreferee() != null) patient.setLanguePreferee(contactInfo.languePreferee());
        if (contactInfo.notificationsResultats() != null) patient.setNotificationsResultats(contactInfo.notificationsResultats());
        if (contactInfo.notificationsRdv() != null) patient.setNotificationsRdv(contactInfo.notificationsRdv());
        if (contactInfo.notificationsRappels() != null) patient.setNotificationsRappels(contactInfo.notificationsRappels());
    }

    /**
     * Met à jour les consentements
     */
    private void updateConsent(Patient patient, ConsentUpdateRequest consent) {
        if (consent.consentementSms() != null) patient.setConsentementSms(consent.consentementSms());
        if (consent.consentementEmail() != null) patient.setConsentementEmail(consent.consentementEmail());
    }

    /**
     * Met à jour les assurances
     */
    private void updateInsurances(Patient patient, List<InsuranceRequest> insurances) {
        // Suppression des anciennes assurances
        patient.getAssurances().clear();

        // Ajout des nouvelles assurances
        for (InsuranceRequest insuranceRequest : insurances) {
            PatientAssurance assurance = buildAssuranceFromRequest(insuranceRequest);
            patient.addAssurance(assurance);
        }
    }

    /**
     * Mappe un Patient vers PatientResponse
     */
    private PatientResponse mapToResponse(Patient patient) {
        return PatientResponse.builder()
                .id(patient.getId().toString())
                .personalInfo(mapToPersonalInfoResponse(patient))
                .contactInfo(mapToContactInfoResponse(patient))
                .insurances(patient.getAssurances().stream()
                        .map(this::mapToInsuranceResponse)
                        .collect(Collectors.toList()))
                .consent(mapToConsentResponse(patient))
                .metadata(mapToMetadataResponse(patient))
                .build();
    }

    /**
     * Mappe vers PersonalInfoResponse
     */
    private PersonalInfoResponse mapToPersonalInfoResponse(Patient patient) {
        return PersonalInfoResponse.builder()
                .nom(patient.getNom())
                .prenom(patient.getPrenom())
                .nomJeuneFille(patient.getNomJeuneFille())
                .dateNaissance(patient.getDateNaissance())
                .lieuNaissance(patient.getLieuNaissance())
                .sexe(patient.getSexe())
                .numeroSecuMasque(patient.getNumeroSecuMasque())
                .age(patient.getAge())
                .medecinTraitant(patient.getMedecinTraitant())
                .allergiesConnues(patient.getAllergiesConnues())
                .antecedentsMedicaux(patient.getAntecedentsMedicaux())
                .build();
    }

    /**
     * Mappe vers ContactInfoResponse
     */
    private ContactInfoResponse mapToContactInfoResponse(Patient patient) {
        return ContactInfoResponse.builder()
                .email(patient.getEmail())
                .telephone(patient.getTelephone())
                .adresseComplete(patient.getAdresseComplete())
                .adresseLigne1(patient.getAdresseLigne1())
                .adresseLigne2(patient.getAdresseLigne2())
                .codePostal(patient.getCodePostal())
                .ville(patient.getVille())
                .departement(patient.getDepartement())
                .region(patient.getRegion())
                .pays(patient.getPays())
                .latitude(patient.getLatitude())
                .longitude(patient.getLongitude())
                .methodeLivraisonPreferee(patient.getMethodeLivraisonPreferee())
                .preferenceNotification(patient.getPreferenceNotification())
                .languePreferee(patient.getLanguePreferee())
                .notificationsResultats(patient.getNotificationsResultats())
                .notificationsRdv(patient.getNotificationsRdv())
                .notificationsRappels(patient.getNotificationsRappels())
                .build();
    }

    /**
     * Mappe vers InsuranceResponse
     */
    private InsuranceResponse mapToInsuranceResponse(PatientAssurance assurance) {
        return InsuranceResponse.builder()
                .id(assurance.getId().toString())
                .typeAssurance(assurance.getTypeAssurance())
                .nomOrganisme(assurance.getNomOrganisme())
                .numeroAdherent(assurance.getNumeroAdherent())
                .dateDebut(assurance.getDateDebut())
                .dateFin(assurance.getDateFin())
                .estActive(assurance.getEstActive())
                .tiersPayantAutorise(assurance.getTiersPayantAutorise())
                .pourcentagePriseCharge(assurance.getPourcentagePriseCharge())
                .referenceDocument(assurance.getReferenceDocument())
                .build();
    }

    /**
     * Mappe vers ConsentResponse
     */
    private ConsentResponse mapToConsentResponse(Patient patient) {
        return ConsentResponse.builder()
                .consentementCreationCompte(patient.getConsentementCreationCompte())
                .consentementSms(patient.getConsentementSms())
                .consentementEmail(patient.getConsentementEmail())
                .dateConsentement(patient.getDateConsentement())
                .build();
    }

    /**
     * Mappe vers MetadataResponse
     */
    private MetadataResponse mapToMetadataResponse(Patient patient) {
        return MetadataResponse.builder()
                .statut(patient.getStatut())
                .dateCreation(patient.getDateCreation())
                .dateModification(patient.getDateModification())
                .creePar(patient.getCreePar())
                .modifiePar(patient.getModifiePar())
                .actif(patient.isActive())
                .build();
    }

    /**
     * Mappe vers PatientSummaryResponse
     */
    private PatientSummaryResponse mapToSummaryResponse(Patient patient) {
        return PatientSummaryResponse.builder()
                .id(patient.getId().toString())
                .nomComplet(patient.getNomComplet())
                .email(patient.getEmail())
                .telephone(patient.getTelephone())
                .dateNaissance(patient.getDateNaissance())
                .age(patient.getAge())
                .sexe(patient.getSexe())
                .ville(patient.getVille())
                .statut(patient.getStatut())
                .dateCreation(patient.getDateCreation())
                .build();
    }
}