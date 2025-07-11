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
import org.springframework.util.StringUtils;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.Period;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service principal pour la gestion des patients
 * Architecture séparée : CRUD dans PatientService, recherches dans PatientSearchService
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class PatientService {

    private final PatientRepository patientRepository;
    private final PatientSearchService patientSearchService; // Délégation pour les recherches

    // ====================================================================
    // MÉTHODES CRUD PRINCIPALES
    // ====================================================================

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
        Patient savedPatient = patientRepository.save(patient);

        log.info("Patient créé avec succès: {} (ID: {})",
                savedPatient.getNomComplet(), savedPatient.getId());

        return mapToPatientResponse(savedPatient);
    }

    /**
     * Récupère un patient par son ID
     */
    @Transactional(readOnly = true)
    public PatientResponse getPatient(UUID id) {
        log.debug("Récupération du patient: {}", id);

        Patient patient = patientRepository.findByIdAndDateSuppressionIsNull(id)
                .orElseThrow(() -> new PatientNotFoundException("Patient non trouvé: " + id));

        return mapToPatientResponse(patient);
    }

    /**
     * Met à jour un patient existant
     */
    public PatientResponse updatePatient(UUID id, UpdatePatientRequest request) {
        log.info("Mise à jour du patient: {}", id);

        Patient patient = patientRepository.findByIdAndDateSuppressionIsNull(id)
                .orElseThrow(() -> new PatientNotFoundException("Patient non trouvé: " + id));

        // Mettre à jour les champs modifiables
        updatePatientFields(patient, request);

        Patient savedPatient = patientRepository.save(patient);

        log.info("Patient mis à jour: {} (ID: {})", savedPatient.getNomComplet(), id);

        return mapToPatientResponse(savedPatient);
    }

    /**
     * Suppression logique d'un patient
     */
    public void deletePatient(UUID id, String deleteReason) {
        log.info("Suppression logique du patient: {} - Raison: {}", id, deleteReason);

        Patient patient = patientRepository.findByIdAndDateSuppressionIsNull(id)
                .orElseThrow(() -> new PatientNotFoundException("Patient non trouvé: " + id));

        patient.setDateSuppression(LocalDateTime.now());
        patient.setStatut(PatientStatus.INACTIF);

        patientRepository.save(patient);

        log.info("Patient supprimé logiquement: {}", id);
    }

    // ====================================================================
    // MÉTHODES DE RECHERCHE - DÉLÉGATION À PatientSearchService
    // ====================================================================

    /**
     * Recherche multicritères - DÉLÉGUÉ au PatientSearchService
     */
    @Transactional(readOnly = true)
    public PatientSearchResponse searchPatients(PatientSearchRequest request) {
        log.debug("Délégation de la recherche au PatientSearchService");
        return patientSearchService.searchPatients(request);
    }

    /**
     * Recherche rapide par nom complet - DÉLÉGUÉ
     */
    @Transactional(readOnly = true)
    public List<PatientSummaryResponse> quickSearchByNomComplet(String nomComplet) {
        return patientSearchService.quickSearchByNomComplet(nomComplet);
    }

    /**
     * Recherche par nom et prénom - DÉLÉGUÉ
     */
    @Transactional(readOnly = true)
    public List<PatientSummaryResponse> searchByNomPrenom(String nom, String prenom) {
        return patientSearchService.searchByNomPrenom(nom, prenom);
    }

    /**
     * Recherche par nom et prénom - DÉLÉGUÉ
     */
    @Transactional(readOnly = true)
    public List<PatientSummaryResponse> searchByPhone(String phone) {
        return patientSearchService.searchByPhone(phone);
    }

    /**
     * Suggestions d'autocomplétion - DÉLÉGUÉ
     */
    @Transactional(readOnly = true)
    public List<String> suggestNomComplet(String input) {
        return patientSearchService.suggestNomComplet(input);
    }

    /**
     * Recherche rapide générale - DÉLÉGUÉ
     */
    @Transactional(readOnly = true)
    public List<PatientSummaryResponse> quickSearch(String query, int limit) {
        return patientSearchService.quickSearch(query, limit);
    }

    // ====================================================================
    // MÉTHODES DE RECHERCHE SPÉCIFIQUES (restent dans PatientService)
    // ====================================================================

    /**
     * Recherche par email - unique et critique pour l'authentification
     */
    @Transactional(readOnly = true)
    public Optional<PatientResponse> findByEmail(String email) {
        log.debug("Recherche par email: {}", email);

        if (!StringUtils.hasText(email)) {
            return Optional.empty();
        }

        Optional<Patient> patient = patientRepository.findByEmailAndDateSuppressionIsNull(email.toLowerCase().trim());

        return patient.map(this::mapToPatientResponse);
    }

    /**
     * Recherche par téléphone - unique et critique
     */
    @Transactional(readOnly = true)
    public Optional<PatientResponse> findByTelephone(String telephone) {
        log.debug("Recherche par téléphone: {}", telephone);

        if (!StringUtils.hasText(telephone)) {
            return Optional.empty();
        }

        Optional<Patient> patient = patientRepository.findByTelephoneAndDateSuppressionIsNull(telephone.trim());

        return patient.map(this::mapToPatientResponse);
    }

    /**
     * Recherche par numéro de sécurité sociale - unique et critique
     */
    @Transactional(readOnly = true)
    public Optional<PatientResponse> findByNumeroSecu(String numeroSecu) {
        log.debug("Recherche par numéro de sécurité sociale");

        if (!StringUtils.hasText(numeroSecu)) {
            return Optional.empty();
        }

        Optional<Patient> patient = patientRepository.findByNumeroSecuAndDateSuppressionIsNull(numeroSecu.trim());

        return patient.map(this::mapToPatientResponse);
    }

    // ====================================================================
    // MÉTHODES UTILITAIRES ET LISTES
    // ====================================================================

    /**
     * Liste des patients actifs avec pagination
     */
    @Transactional(readOnly = true)
    public List<PatientSummaryResponse> getActivePatients(int page, int size) {
        log.debug("Récupération des patients actifs - page: {}, size: {}", page, size);

        Pageable pageable = PageRequest.of(page, size, Sort.by("nom", "prenom"));
        Page<Patient> patients = patientRepository.findByStatutAndDateSuppressionIsNull(
                PatientStatus.ACTIF, pageable);

        return patients.stream()
                .map(this::mapToSummaryResponse)
                .collect(Collectors.toList());
    }

    /**
     * Compte le nombre de patients actifs
     */
    @Transactional(readOnly = true)
    public long countActivePatients() {
        return patientRepository.countByStatutAndDateSuppressionIsNull(PatientStatus.ACTIF);
    }

    /**
     * Vérifie si un patient existe par email
     */
    @Transactional(readOnly = true)
    public boolean existsByEmail(String email) {
        if (!StringUtils.hasText(email)) {
            return false;
        }
        return patientRepository.existsByEmailAndDateSuppressionIsNull(email.toLowerCase().trim());
    }

    /**
     * Vérifie si un patient existe par téléphone
     */
    @Transactional(readOnly = true)
    public boolean existsByTelephone(String telephone) {
        if (!StringUtils.hasText(telephone)) {
            return false;
        }
        return patientRepository.existsByTelephoneAndDateSuppressionIsNull(telephone.trim());
    }

    /**
     * Vérifie si un patient existe par numéro de sécurité sociale
     */
    @Transactional(readOnly = true)
    public boolean existsByNumeroSecu(String numeroSecu) {
        if (!StringUtils.hasText(numeroSecu)) {
            return false;
        }
        return patientRepository.existsByNumeroSecuAndDateSuppressionIsNull(numeroSecu.trim());
    }

    // ====================================================================
    // MÉTHODES PRIVÉES DE SUPPORT
    // ====================================================================

    private void validateCreateRequest(CreatePatientRequest request) {
        if (request.personalInfo() == null) {
            throw new InvalidPatientDataException("Les informations personnelles sont obligatoires");
        }

        if (request.contactInfo() == null) {
            throw new InvalidPatientDataException("Les informations de contact sont obligatoires");
        }

        if (request.consent() == null) {
            throw new InvalidPatientDataException("Les consentements sont obligatoires");
        }

        PersonalInfoRequest personalInfo = request.personalInfo();
        ContactInfoRequest contactInfo = request.contactInfo();
        ConsentRequest consent = request.consent();

        // Validation des informations personnelles obligatoires
        if (!StringUtils.hasText(personalInfo.nom()) || !StringUtils.hasText(personalInfo.prenom())) {
            throw new InvalidPatientDataException("Le nom et le prénom sont obligatoires");
        }

        if (!StringUtils.hasText(personalInfo.numeroSecu())) {
            throw new InvalidPatientDataException("Le numéro de sécurité sociale est obligatoire");
        }

        if (personalInfo.dateNaissance() == null) {
            throw new InvalidPatientDataException("La date de naissance est obligatoire");
        }

        if (personalInfo.sexe() == null) {
            throw new InvalidPatientDataException("Le sexe est obligatoire");
        }

        // Validation des informations de contact obligatoires
        if (!StringUtils.hasText(contactInfo.email())) {
            throw new InvalidPatientDataException("L'email est obligatoire");
        }

        if (!StringUtils.hasText(contactInfo.telephone())) {
            throw new InvalidPatientDataException("Le téléphone est obligatoire");
        }

        if (!StringUtils.hasText(contactInfo.adresseLigne1()) ||
                !StringUtils.hasText(contactInfo.codePostal()) ||
                !StringUtils.hasText(contactInfo.ville())) {
            throw new InvalidPatientDataException("L'adresse complète est obligatoire");
        }

        // Validation des consentements obligatoires
        if (consent.consentementCreationCompte() == null || !consent.consentementCreationCompte()) {
            throw new InvalidPatientDataException("Le consentement de création de compte est obligatoire");
        }
    }

    private void checkForDuplicates(CreatePatientRequest request) {
        // Vérification par email
        if (existsByEmail(request.contactInfo().email())) {
            throw new DuplicatePatientException("Un patient avec cet email existe déjà");
        }

        // Vérification par téléphone
        if (existsByTelephone(request.contactInfo().telephone())) {
            throw new DuplicatePatientException("Un patient avec ce téléphone existe déjà");
        }

        // Vérification par numéro de sécurité sociale
        if (existsByNumeroSecu(request.personalInfo().numeroSecu())) {
            throw new DuplicatePatientException("Un patient avec ce numéro de sécurité sociale existe déjà");
        }
    }

    private Patient buildPatientFromRequest(CreatePatientRequest request) {
        PersonalInfoRequest personalInfo = request.personalInfo();
        ContactInfoRequest contactInfo = request.contactInfo();
        ConsentRequest consent = request.consent();

        Patient patient = new Patient();
        // L'ID sera généré automatiquement par @GeneratedValue(strategy = GenerationType.UUID)

        // === INFORMATIONS PERSONNELLES ===
        patient.setNom(personalInfo.nom().toUpperCase().trim());
        patient.setPrenom(capitalizeFirstLetter(personalInfo.prenom().trim()));
        patient.setNomJeuneFille(personalInfo.nomJeuneFille());
        patient.setDateNaissance(personalInfo.dateNaissance());
        patient.setLieuNaissance(personalInfo.lieuNaissance());
        patient.setSexe(personalInfo.sexe());
        patient.setNumeroSecu(personalInfo.numeroSecu());
        patient.setMedecinTraitant(personalInfo.medecinTraitant());
        patient.setAllergiesConnues(personalInfo.allergiesConnues());
        patient.setAntecedentsMedicaux(personalInfo.antecedentsMedicaux());

        // === INFORMATIONS DE CONTACT CENTRALISÉES ===
        patient.setEmail(contactInfo.email().toLowerCase().trim());
        patient.setTelephone(contactInfo.telephone());
        patient.setAdresseLigne1(contactInfo.adresseLigne1());
        patient.setAdresseLigne2(contactInfo.adresseLigne2());
        patient.setCodePostal(contactInfo.codePostal());
        patient.setVille(contactInfo.ville());
        patient.setDepartement(contactInfo.departement());
        patient.setRegion(contactInfo.region());
        patient.setPays(contactInfo.pays() != null ? contactInfo.pays() : "France");
        patient.setLatitude(contactInfo.latitude());
        patient.setLongitude(contactInfo.longitude());

        // === PRÉFÉRENCES DE COMMUNICATION ===
        patient.setMethodeLivraisonPreferee(contactInfo.methodeLivraisonPreferee());
        patient.setPreferenceNotification(contactInfo.preferenceNotification());
        patient.setLanguePreferee(contactInfo.languePreferee() != null ? contactInfo.languePreferee() : "fr-FR");
        patient.setNotificationsResultats(contactInfo.notificationsResultats() != null ? contactInfo.notificationsResultats() : true);
        patient.setNotificationsRdv(contactInfo.notificationsRdv() != null ? contactInfo.notificationsRdv() : true);
        patient.setNotificationsRappels(contactInfo.notificationsRappels() != null ? contactInfo.notificationsRappels() : true);

        // === CONSENTEMENTS RGPD ===
        patient.setConsentementCreationCompte(consent.consentementCreationCompte());
        patient.setConsentementSms(consent.consentementSms());
        patient.setConsentementEmail(consent.consentementEmail());
        patient.setDateConsentement(LocalDateTime.now());

        // === MÉTADONNÉES ===
        patient.setStatut(PatientStatus.ACTIF);
        patient.setDateCreation(LocalDateTime.now());
        patient.setCreepar(request.createdBy() != null ? request.createdBy() : "SYSTEM");

        return patient;
    }

    private PatientAssurance buildAssuranceFromRequest(InsuranceRequest request) {
        PatientAssurance assurance = new PatientAssurance();
        // L'ID sera généré automatiquement si l'entité a @GeneratedValue
        assurance.setTypeAssurance(request.typeAssurance());
        assurance.setNomOrganisme(request.nomOrganisme());
        assurance.setNumeroAdherent(request.numeroAdherent());
        assurance.setDateDebut(request.dateDebut());
        assurance.setDateFin(request.dateFin());
        assurance.setTiersPayantAutorise(request.tiersPayantAutorise());
        assurance.setPourcentagePriseCharge(request.pourcentagePriseCharge());
        assurance.setReferenceDocument(request.referenceDocument());
        assurance.setEstActive(true);
        return assurance;
    }

    private void updatePatientFields(Patient patient, UpdatePatientRequest request) {
        // Mise à jour des informations personnelles
        if (request.personalInfo() != null) {
            PersonalInfoUpdateRequest personalInfo = request.personalInfo(); // ← Correction du type
            if (StringUtils.hasText(personalInfo.nom())) {
                patient.setNom(personalInfo.nom().toUpperCase().trim());
            }
            if (StringUtils.hasText(personalInfo.prenom())) {
                patient.setPrenom(capitalizeFirstLetter(personalInfo.prenom().trim()));
            }
            if (personalInfo.dateNaissance() != null) {
                patient.setDateNaissance(personalInfo.dateNaissance());
            }
            if (personalInfo.sexe() != null) {
                patient.setSexe(personalInfo.sexe());
            }
            if (StringUtils.hasText(personalInfo.nomJeuneFille())) {
                patient.setNomJeuneFille(personalInfo.nomJeuneFille());
            }
            if (StringUtils.hasText(personalInfo.lieuNaissance())) {
                patient.setLieuNaissance(personalInfo.lieuNaissance());
            }
            if (StringUtils.hasText(personalInfo.medecinTraitant())) {
                patient.setMedecinTraitant(personalInfo.medecinTraitant());
            }
            if (personalInfo.allergiesConnues() != null) {
                patient.setAllergiesConnues(personalInfo.allergiesConnues());
            }
            if (personalInfo.antecedentsMedicaux() != null) {
                patient.setAntecedentsMedicaux(personalInfo.antecedentsMedicaux());
            }
        }

        // Mise à jour des informations de contact
        if (request.contactInfo() != null) {
            ContactInfoUpdateRequest contactInfo = request.contactInfo(); // ← Probablement aussi à corriger
            if (StringUtils.hasText(contactInfo.email())) {
                patient.setEmail(contactInfo.email().toLowerCase().trim());
            }
            if (StringUtils.hasText(contactInfo.telephone())) {
                patient.setTelephone(contactInfo.telephone());
            }
            if (StringUtils.hasText(contactInfo.adresseLigne1())) {
                patient.setAdresseLigne1(contactInfo.adresseLigne1());
            }
            if (contactInfo.adresseLigne2() != null) {
                patient.setAdresseLigne2(contactInfo.adresseLigne2());
            }
            if (StringUtils.hasText(contactInfo.codePostal())) {
                patient.setCodePostal(contactInfo.codePostal());
            }
            if (StringUtils.hasText(contactInfo.ville())) {
                patient.setVille(contactInfo.ville());
            }
            if (contactInfo.departement() != null) {
                patient.setDepartement(contactInfo.departement());
            }
            if (contactInfo.region() != null) {
                patient.setRegion(contactInfo.region());
            }
            if (contactInfo.pays() != null) {
                patient.setPays(contactInfo.pays());
            }
            if (contactInfo.preferenceNotification() != null) {
                patient.setPreferenceNotification(contactInfo.preferenceNotification());
            }
            if (contactInfo.languePreferee() != null) {
                patient.setLanguePreferee(contactInfo.languePreferee());
            }
        }

        patient.setDateModification(LocalDateTime.now());
        patient.setModifiePar("SYSTEM"); // À adapter selon le contexte d'authentification
    }

    private String capitalizeFirstLetter(String str) {
        if (str == null || str.isEmpty()) {
            return str;
        }
        return str.substring(0, 1).toUpperCase() + str.substring(1).toLowerCase();
    }

    /**
     * Mapping complet vers PatientResponse
     */
    private PatientResponse mapToPatientResponse(Patient patient) {
        // Construction des informations personnelles
        PersonalInfoResponse personalInfo = PersonalInfoResponse.builder()
                .nom(patient.getNom())
                .prenom(patient.getPrenom())
                .nomJeuneFille(patient.getNomJeuneFille())
                .dateNaissance(patient.getDateNaissance())
                .lieuNaissance(patient.getLieuNaissance())
                .sexe(patient.getSexe())
                .numeroSecuMasque(maskNumeroSecu(patient.getNumeroSecu()))
                .age(patient.getAge())
                .medecinTraitant(patient.getMedecinTraitant())
                .allergiesConnues(patient.getAllergiesConnues())
                .antecedentsMedicaux(patient.getAntecedentsMedicaux())
                .build();

        // Construction des informations de contact
        ContactInfoResponse contactInfo = ContactInfoResponse.builder()
                .email(patient.getEmail())
                .telephone(patient.getTelephone())
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

        // Construction des consentements
        ConsentResponse consent = ConsentResponse.builder()
                .consentementCreationCompte(patient.getConsentementCreationCompte())
                .consentementSms(patient.getConsentementSms())
                .consentementEmail(patient.getConsentementEmail())
                .dateConsentement(patient.getDateConsentement())
                .build();

        // Construction des métadonnées
        MetadataResponse metadata = MetadataResponse.builder()
                .statut(patient.getStatut())
                .dateCreation(patient.getDateCreation())
                .dateModification(patient.getDateModification())
                .creePar(patient.getCreePar())
                .modifiePar(patient.getModifiePar())
                .actif(patient.getStatut() == PatientStatus.ACTIF)
                .build();

        return PatientResponse.builder()
                .id(patient.getId().toString()) // Convertir UUID en String pour le DTO
                .personalInfo(personalInfo)
                .contactInfo(contactInfo)
                .consent(consent)
                .metadata(metadata)
                .build();
    }

    /**
     * Mapping simplifié vers PatientSummaryResponse
     */
    private PatientSummaryResponse mapToSummaryResponse(Patient patient) {
        String nomComplet = String.format("%s %s",
                patient.getNom() != null ? patient.getNom() : "",
                patient.getPrenom() != null ? patient.getPrenom() : "").trim();

        Integer age = null;
        if (patient.getDateNaissance() != null) {
            age = Period.between(patient.getDateNaissance(), LocalDate.now()).getYears();
        }

        return PatientSummaryResponse.builder()
                .id(patient.getId().toString()) // Convertir UUID en String pour le DTO
                .nomComplet(nomComplet)
                .email(patient.getEmail())
                .telephone(patient.getTelephone())
                .dateNaissance(patient.getDateNaissance())
                .age(age)
                .sexe(patient.getSexe())
                .ville(patient.getVille())
                .statut(patient.getStatut())
                .dateCreation(patient.getDateCreation())
                .build();
    }

    private String maskNumeroSecu(String numeroSecu) {
        if (numeroSecu == null || numeroSecu.length() < 8) {
            return "****";
        }
        return numeroSecu.substring(0, 4) + "***" + numeroSecu.substring(numeroSecu.length() - 2);
    }
}