package com.lims.patient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.fge.jsonpatch.JsonPatch;
import com.github.fge.jsonpatch.JsonPatchException;
import com.lims.patient.dto.request.*;
import com.lims.patient.dto.response.*;
import com.lims.patient.entity.Patient;
import com.lims.patient.entity.PatientAssurance;
import com.lims.patient.enums.DeliveryMethod;
import com.lims.patient.enums.NotificationPreference;
import com.lims.patient.enums.PatientStatus;
import com.lims.patient.exception.DuplicatePatientException;
import com.lims.patient.exception.InvalidPatientDataException;
import com.lims.patient.exception.PatientNotFoundException;
import com.lims.patient.mapper.PatientMapper;
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
import java.util.ArrayList;
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
    private final PatientMapper patientMapper;
    private final ObjectMapper objectMapper;

    // ====================================================================
    // MÉTHODES CRUD PRINCIPALES
    // ====================================================================

    /**
     * Crée un nouveau patient avec structure centralisée
     */
    public PatientResponse createPatient(CreatePatientRequest request, String createdBy) {
        log.debug("Création d'un nouveau patient: {} {} avec {} spécificités par {}",
                request.personalInfo().prenom(),
                request.personalInfo().nom(),
                request.specificities() != null && request.specificities().specificityIds() != null
                        ? request.specificities().specificityIds().size() : 0,
                createdBy);

        // 1. Validation des données (existante)
        validateCreateRequest(request);

        // 2. Vérification des doublons (existante)
        checkForDuplicates(request);

        // 3. Construction de l'entité Patient avec createdBy
        Patient patient = buildPatientFromRequest(request, createdBy);

        // 4. AJOUT SPÉCIFICITÉS - UNIQUEMENT LES IDs
        if (request.specificities() != null && request.specificities().specificityIds() != null) {
            patient.setSpecificityIds(new ArrayList<>(request.specificities().specificityIds()));
            log.debug("Spécificités ajoutées au patient: {}", request.specificities().specificityIds());
        }

        // 5. AJOUT COMMENTAIRE PATIENT - DIRECTEMENT SUR PATIENT
        if (StringUtils.hasText(request.commentairePatient())) {
            patient.setCommentairePatient(request.commentairePatient());
            log.debug("Commentaire patient ajouté");
        }

        // 7. Sauvegarde
        Patient savedPatient;
        try {
            savedPatient = patientRepository.saveAndFlush(patient); // ✅ Force l'SQL immédiatement
            log.info("Patient sauvegardé en BDD avec succès: {} (ID: {})",
                    savedPatient.getNomComplet(), savedPatient.getId());
        } catch (Exception e) {
            log.error("ERREUR SQL lors de la sauvegarde du patient: {}", e.getMessage());
            throw e; // L'erreur apparaîtra ici, pas plus tard
        }

        log.info("Patient créé avec succès: {} (ID: {}), {} spécificité(s), commentaire: {}",
                savedPatient.getNomComplet(),
                savedPatient.getId(),
                savedPatient.getSpecificitiesCount(),
                savedPatient.getCommentairePatient() != null ? "oui" : "non");

        return mapToPatientResponse(savedPatient);
    }

    /**
     * Met à jour un patient avec JSON Patch (RFC 6902)
     */
    public PatientResponse updatePatient(UUID id, JsonNode patchNode, String updatedBy) {
        log.debug("Mise à jour du patient {} avec JSON Patch par {}", id, updatedBy);

        try {
            // 1. Récupérer le patient existant
            Patient existingPatient = patientRepository.findByIdAndDateSuppressionIsNull(id)
                    .orElseThrow(() -> new PatientNotFoundException(
                            String.format("Patient non trouvé avec l'ID: %s", id)));

            // 2. Convertir le patient en JSON
            JsonNode patientNode = objectMapper.valueToTree(existingPatient);

            // 3. Appliquer le patch JSON
            JsonPatch patch = JsonPatch.fromJson(patchNode);
            JsonNode patchedNode = patch.apply(patientNode);

            // 4. Convertir le résultat en entité Patient
            Patient patchedPatient = objectMapper.treeToValue(patchedNode, Patient.class);

            // 5. Valider les données après patch
            validatePatchedPatient(patchedPatient, existingPatient);

            // 6. Mettre à jour les métadonnées
            patchedPatient.setModifiePar(updatedBy);
            patchedPatient.setDateModification(LocalDateTime.now());

            // 7. Sauvegarder
            Patient savedPatient = patientRepository.save(patchedPatient);

            log.info("Patient {} mis à jour avec succès par {}", id, updatedBy);
            return patientMapper.toPatientResponse(savedPatient);

        } catch (JsonPatchException e) {
            log.error("Erreur lors de l'application du patch JSON pour le patient {}: {}", id, e.getMessage());
            throw new InvalidPatientDataException("Opérations patch invalides: " + e.getMessage());
        } catch (Exception e) {
            log.error("Erreur lors de la mise à jour du patient {}: {}", id, e.getMessage());
            throw new InvalidPatientDataException("Erreur lors de la mise à jour: " + e.getMessage());
        }
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
        if (consent.createAccount() == null || !consent.createAccount()) {
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

    private Patient buildPatientFromRequest(CreatePatientRequest request, String createdBy) {
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
        patient.setMethodeLivraisonPreferee(DeliveryMethod.EMAIL);
        patient.setPreferenceNotification(NotificationPreference.TOUS);
        patient.setLanguePreferee(contactInfo.languePreferee() != null ? contactInfo.languePreferee() : "fr-FR");
        patient.setNotificationsResultats(contactInfo.notificationsResultats() != null ? contactInfo.notificationsResultats() : true);
        patient.setNotificationsRdv(contactInfo.notificationsRdv() != null ? contactInfo.notificationsRdv() : true);
        patient.setNotificationsRappels(contactInfo.notificationsRappels() != null ? contactInfo.notificationsRappels() : true);

        // === CONSENTEMENTS RGPD ===
        patient.setConsentementCreationCompte(consent.createAccount());
        patient.setConsentementSms(consent.sms());
        patient.setConsentementEmail(consent.email());
        patient.setDateConsentement(LocalDateTime.now());

        // === MÉTADONNÉES ===
        patient.setStatut(PatientStatus.ACTIF);
        patient.setDateCreation(LocalDateTime.now());
        patient.setCreepar(request.createdBy() != null ? request.createdBy() : "SYSTEM");

        patient.setCreepar(createdBy);

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
                .createAccount(patient.getConsentementCreationCompte())
                .sms(patient.getConsentementSms())
                .email(patient.getConsentementEmail())
                .dateConsentement(patient.getDateConsentement())
                .build();

        PatientSpecificitiesResponse specificitiesResponse = PatientSpecificitiesResponse.builder()
                .specificityIds(patient.getSpecificityIds())
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
                .commentairePatient(patient.getCommentairePatient())
                .specificities(specificitiesResponse)
                .contactInfo(contactInfo)
                .consent(consent)
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

    /**
     * Valide le patient après application du patch
     */
    private void validatePatchedPatient(Patient patchedPatient, Patient originalPatient) {
        // Préserver l'ID original (ne doit pas être modifié)
        patchedPatient.setId(originalPatient.getId());

        // Préserver les métadonnées de création
        patchedPatient.setCreepar(originalPatient.getCreePar());
        patchedPatient.setDateCreation(originalPatient.getDateCreation());

        // Préserver la date de suppression si elle existe
        patchedPatient.setDateSuppression(originalPatient.getDateSuppression());

        // Vérifier l'unicité de l'email si modifié
        if (StringUtils.hasText(patchedPatient.getEmail()) &&
                !patchedPatient.getEmail().equals(originalPatient.getEmail())) {

            Optional<Patient> existingWithEmail = patientRepository
                    .findByEmailAndDateSuppressionIsNull(patchedPatient.getEmail());

            if (existingWithEmail.isPresent()) {
                throw new DuplicatePatientException(
                        "Un patient existe déjà avec cet email: " + patchedPatient.getEmail());
            }
        }

        // Vérifier l'unicité du numéro de sécurité sociale si modifié
        if (StringUtils.hasText(patchedPatient.getNumeroSecu()) &&
                !patchedPatient.getNumeroSecu().equals(originalPatient.getNumeroSecu())) {

            Optional<Patient> existingWithSecu = patientRepository
                    .findByNumeroSecuAndDateSuppressionIsNull(patchedPatient.getNumeroSecu());

            if (existingWithSecu.isPresent()) {
                throw new DuplicatePatientException(
                        "Un patient existe déjà avec ce numéro de sécurité sociale");
            }
        }

        // Validation de la date de naissance si modifiée
        if (patchedPatient.getDateNaissance() != null) {
            LocalDate now = LocalDate.now();
            if (patchedPatient.getDateNaissance().isAfter(now)) {
                throw new InvalidPatientDataException("La date de naissance ne peut pas être dans le futur");
            }

            int age = Period.between(patchedPatient.getDateNaissance(), now).getYears();
            if (age > 150) {
                throw new InvalidPatientDataException("Âge invalide (plus de 150 ans)");
            }
        }

        // Validation des champs obligatoires
        if (!StringUtils.hasText(patchedPatient.getNom())) {
            throw new InvalidPatientDataException("Le nom est obligatoire");
        }
        if (!StringUtils.hasText(patchedPatient.getPrenom())) {
            throw new InvalidPatientDataException("Le prénom est obligatoire");
        }
        if (!StringUtils.hasText(patchedPatient.getEmail())) {
            throw new InvalidPatientDataException("L'email est obligatoire");
        }
        if (patchedPatient.getDateNaissance() == null) {
            throw new InvalidPatientDataException("La date de naissance est obligatoire");
        }
        if (!StringUtils.hasText(patchedPatient.getNumeroSecu())) {
            throw new InvalidPatientDataException("Le numéro de sécurité sociale est obligatoire");
        }
    }

}