package com.lims.patient.service;

import com.lims.patient.dto.request.CreatePatientRequest;
import com.lims.patient.dto.request.UpdatePatientRequest;
import com.lims.patient.entity.Patient;
import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.PrescriptionStatus;
import com.lims.patient.exception.InvalidPatientDataException;
import com.lims.patient.exception.ConsentValidationException;
import com.lims.patient.exception.PatientBusinessRuleException;
import com.lims.patient.repository.PatientRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.LocalDate;
import java.time.Period;
import java.util.regex.Pattern;

/**
 * Service de validation des règles métier pour les patients - Version centralisée
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PatientValidationService {

    private final PatientRepository patientRepository;

    // Patterns de validation
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
    );

    private static final Pattern PHONE_PATTERN = Pattern.compile(
            "^\\+[1-9][0-9]{8,14}$"
    );

    private static final Pattern CODE_POSTAL_PATTERN = Pattern.compile(
            "^[0-9]{5}$"
    );

    private static final Pattern NIR_PATTERN = Pattern.compile(
            "^[12][0-9]{12}[0-9]{2}$"
    );

    /**
     * Valide les données d'un nouveau patient avec structure centralisée
     */
    public void validateNewPatient(CreatePatientRequest request) {
        log.debug("Validation des données du nouveau patient");

        if (request == null) {
            throw new InvalidPatientDataException("La requête de création ne peut pas être nulle");
        }

        // Validation des informations personnelles
        validatePersonalInfo(request);

        // Validation des informations de contact centralisées
        validateContactInfo(request);

        // Validation des consentements RGPD
        validateConsents(request);

        // Validation des assurances si présentes
        if (request.insurances() != null && !request.insurances().isEmpty()) {
            validateInsurances(request);
        }

        log.debug("Validation du nouveau patient terminée avec succès");
    }

    /**
     * Valide les modifications d'un patient existant
     */
    public void validatePatientUpdate(Patient existingPatient, UpdatePatientRequest request) {
        log.debug("Validation des modifications du patient {}", existingPatient.getId());

        if (existingPatient == null) {
            throw new InvalidPatientDataException("Le patient existant ne peut pas être nul");
        }

        if (request == null) {
            throw new InvalidPatientDataException("La requête de mise à jour ne peut pas être nulle");
        }

        // Validation des informations personnelles si modifiées
        if (request.personalInfo() != null) {
            validatePersonalInfoUpdate(request.personalInfo(), existingPatient);
        }

        // Validation des informations de contact si modifiées
        if (request.contactInfo() != null) {
            validateContactInfoUpdate(request.contactInfo());
        }

        // Validation des consentements si modifiés
        if (request.consent() != null) {
            validateConsentUpdate(request.consent(), existingPatient);
        }

        log.debug("Validation des modifications terminée avec succès");
    }

    /**
     * Valide la suppression d'un patient
     */
    public void validatePatientDeletion(Patient patient) {
        log.debug("Validation de la suppression du patient {}", patient.getId());

        if (patient == null) {
            throw new InvalidPatientDataException("Le patient à supprimer ne peut pas être nul");
        }

        // Vérifier s'il y a des ordonnances actives
        boolean hasActivePrescriptions = patient.getOrdonnances().stream()
                .anyMatch(ordonnance -> ordonnance.getDateSuppression() == null &&
                        (ordonnance.getStatut() == PrescriptionStatus.EN_ATTENTE ||
                                ordonnance.getStatut() == PrescriptionStatus.VALIDEE));

        if (hasActivePrescriptions) {
            throw new PatientBusinessRuleException(
                    "SUPPRESSION_INTERDITE",
                    "Impossible de supprimer le patient : il a des ordonnances actives");
        }

        // Vérification des assurances actives
        boolean hasActiveInsurance = patient.getAssurances().stream()
                .anyMatch(assurance -> assurance.getEstActive() != null &&
                        assurance.getEstActive() &&
                        (assurance.getDateFin() == null || assurance.getDateFin().isAfter(LocalDate.now())));

        if (hasActiveInsurance) {
            log.warn("Suppression d'un patient avec assurance active: {}", patient.getId());
        }

        log.debug("Validation de suppression terminée avec succès");
    }

    // ============================================
    // MÉTHODES PRIVÉES DE VALIDATION
    // ============================================

    /**
     * Valide les informations personnelles lors de la création
     */
    private void validatePersonalInfo(CreatePatientRequest request) {
        var personalInfo = request.personalInfo();

        if (personalInfo == null) {
            throw new InvalidPatientDataException("Les informations personnelles sont obligatoires");
        }

        // Validation des champs obligatoires
        if (!StringUtils.hasText(personalInfo.nom())) {
            throw new InvalidPatientDataException("Le nom est obligatoire");
        }

        if (!StringUtils.hasText(personalInfo.prenom())) {
            throw new InvalidPatientDataException("Le prénom est obligatoire");
        }

        if (personalInfo.dateNaissance() == null) {
            throw new InvalidPatientDataException("La date de naissance est obligatoire");
        }

        if (personalInfo.sexe() == null) {
            throw new InvalidPatientDataException("Le sexe est obligatoire");
        }

        if (!StringUtils.hasText(personalInfo.numeroSecu())) {
            throw new InvalidPatientDataException("Le numéro de sécurité sociale est obligatoire");
        }

        // Validation de l'âge
        validateAge(personalInfo.dateNaissance());

        // Validation du NIR
        validateNIR(personalInfo.numeroSecu(), personalInfo.dateNaissance(), personalInfo.sexe());
    }

    /**
     * Valide les informations de contact centralisées lors de la création
     */
    private void validateContactInfo(CreatePatientRequest request) {
        var contactInfo = request.contactInfo();

        if (contactInfo == null) {
            throw new InvalidPatientDataException("Les informations de contact sont obligatoires");
        }

        // Validation email obligatoire
        if (!StringUtils.hasText(contactInfo.email())) {
            throw new InvalidPatientDataException("L'email est obligatoire");
        }

        if (!EMAIL_PATTERN.matcher(contactInfo.email()).matches()) {
            throw new InvalidPatientDataException("Format d'email invalide: " + contactInfo.email());
        }

        // Validation téléphone obligatoire
        if (!StringUtils.hasText(contactInfo.telephone())) {
            throw new InvalidPatientDataException("Le téléphone est obligatoire");
        }

        if (!PHONE_PATTERN.matcher(contactInfo.telephone()).matches()) {
            throw new InvalidPatientDataException("Format de téléphone invalide: " + contactInfo.telephone());
        }

        // Validation adresse obligatoire
        if (!StringUtils.hasText(contactInfo.adresseLigne1())) {
            throw new InvalidPatientDataException("L'adresse (ligne 1) est obligatoire");
        }

        if (!StringUtils.hasText(contactInfo.codePostal())) {
            throw new InvalidPatientDataException("Le code postal est obligatoire");
        }

        if (!CODE_POSTAL_PATTERN.matcher(contactInfo.codePostal()).matches()) {
            throw new InvalidPatientDataException("Format de code postal invalide: " + contactInfo.codePostal());
        }

        if (!StringUtils.hasText(contactInfo.ville())) {
            throw new InvalidPatientDataException("La ville est obligatoire");
        }
    }

    /**
     * Valide les consentements RGPD
     */
    private void validateConsents(CreatePatientRequest request) {
        var consent = request.consent();

        if (consent == null) {
            throw new ConsentValidationException("Les consentements sont obligatoires");
        }

        // Consentement de création de compte obligatoire
        if (consent.consentementCreationCompte() == null || !consent.consentementCreationCompte()) {
            throw new ConsentValidationException(
                    "CREATION_COMPTE",
                    "Le consentement pour la création de compte est obligatoire");
        }

        // Validation cohérence consentements
        if (consent.consentementEmail() != null && consent.consentementEmail()) {
            // Si consentement email, vérifier que l'email est valide
            if (!StringUtils.hasText(request.contactInfo().email())) {
                throw new ConsentValidationException(
                        "EMAIL",
                        "Impossible de donner le consentement email sans adresse email valide");
            }
        }

        if (consent.consentementSms() != null && consent.consentementSms()) {
            // Si consentement SMS, vérifier que le téléphone est valide
            if (!StringUtils.hasText(request.contactInfo().telephone())) {
                throw new ConsentValidationException(
                        "SMS",
                        "Impossible de donner le consentement SMS sans numéro de téléphone valide");
            }
        }
    }

    /**
     * Valide les assurances
     */
    private void validateInsurances(CreatePatientRequest request) {
        request.insurances().forEach(insurance -> {
            if (!StringUtils.hasText(insurance.nomOrganisme())) {
                throw new InvalidPatientDataException("Le nom de l'organisme d'assurance est obligatoire");
            }

            if (!StringUtils.hasText(insurance.numeroAdherent())) {
                throw new InvalidPatientDataException("Le numéro d'adhérent est obligatoire");
            }

            if (insurance.dateDebut() == null) {
                throw new InvalidPatientDataException("La date de début d'assurance est obligatoire");
            }

            if (insurance.dateDebut().isAfter(LocalDate.now())) {
                throw new InvalidPatientDataException("La date de début d'assurance ne peut pas être dans le futur");
            }

            if (insurance.dateFin() != null && insurance.dateFin().isBefore(insurance.dateDebut())) {
                throw new InvalidPatientDataException("La date de fin d'assurance doit être postérieure à la date de début");
            }
        });
    }

    /**
     * Valide l'âge du patient
     */
    private void validateAge(LocalDate dateNaissance) {
        if (dateNaissance.isAfter(LocalDate.now())) {
            throw new InvalidPatientDataException("La date de naissance ne peut pas être dans le futur");
        }

        int age = Period.between(dateNaissance, LocalDate.now()).getYears();

        if (age > 120) {
            throw new InvalidPatientDataException("L'âge du patient semble irréaliste (plus de 120 ans)");
        }
    }

    /**
     * Valide le format et la cohérence du NIR
     */
    private void validateNIR(String nir, LocalDate dateNaissance, GenderType sexe) {
        if (!StringUtils.hasText(nir)) {
            throw new InvalidPatientDataException("Le NIR est obligatoire");
        }

        // Normalisation (suppression des espaces)
        String normalizedNir = nir.replaceAll("\\s", "");

        if (!NIR_PATTERN.matcher(normalizedNir).matches()) {
            throw new InvalidPatientDataException("Format NIR invalide. Attendu: 13 chiffres + 2 chiffres de contrôle");
        }

        // Vérification du sexe (1er chiffre : 1=homme, 2=femme)
        char firstDigit = normalizedNir.charAt(0);
        if (sexe == GenderType.M && firstDigit != '1') {
            throw new InvalidPatientDataException("NIR incohérent avec le sexe déclaré (homme)");
        }
        if (sexe == GenderType.F && firstDigit != '2') {
            throw new InvalidPatientDataException("NIR incohérent avec le sexe déclaré (femme)");
        }

        // Vérification de l'année de naissance (2 chiffres suivants)
        try {
            int yearFromNir = Integer.parseInt(normalizedNir.substring(1, 3));
            int actualYear = dateNaissance.getYear() % 100;

            if (yearFromNir != actualYear) {
                throw new InvalidPatientDataException("NIR incohérent avec la date de naissance");
            }
        } catch (NumberFormatException e) {
            throw new InvalidPatientDataException("Format NIR invalide (année de naissance)");
        }

        // Vérification du mois de naissance (2 chiffres suivants)
        try {
            int monthFromNir = Integer.parseInt(normalizedNir.substring(3, 5));
            int actualMonth = dateNaissance.getMonthValue();

            if (monthFromNir != actualMonth) {
                throw new InvalidPatientDataException("NIR incohérent avec le mois de naissance");
            }
        } catch (NumberFormatException e) {
            throw new InvalidPatientDataException("Format NIR invalide (mois de naissance)");
        }
    }

    /**
     * Valide les modifications des informations personnelles
     */
    private void validatePersonalInfoUpdate(
            com.lims.patient.dto.request.PersonalInfoUpdateRequest personalInfo,
            Patient existingPatient) {

        // La date de naissance ne peut pas être modifiée de façon drastique
        if (personalInfo.dateNaissance() != null) {
            validateAge(personalInfo.dateNaissance());

            // Vérification que le changement n'est pas trop important (erreur de saisie)
            Period diff = Period.between(existingPatient.getDateNaissance(), personalInfo.dateNaissance());
            if (Math.abs(diff.getYears()) > 5) {
                log.warn("Modification importante de date de naissance pour patient {}: {} -> {}",
                        existingPatient.getId(), existingPatient.getDateNaissance(), personalInfo.dateNaissance());
            }
        }

        // Le sexe ne peut pas être modifié (cohérence avec NIR)
        if (personalInfo.sexe() != null && personalInfo.sexe() != existingPatient.getSexe()) {
            throw new PatientBusinessRuleException(
                    "MODIFICATION_SEXE_INTERDITE",
                    "La modification du sexe n'est pas autorisée (cohérence avec le NIR)");
        }
    }

    /**
     * Valide les modifications des informations de contact
     */
    private void validateContactInfoUpdate(
            com.lims.patient.dto.request.ContactInfoUpdateRequest contactInfo) {

        // Validation email si modifié
        if (StringUtils.hasText(contactInfo.email())) {
            if (!EMAIL_PATTERN.matcher(contactInfo.email()).matches()) {
                throw new InvalidPatientDataException("Format d'email invalide: " + contactInfo.email());
            }
        }

        // Validation téléphone si modifié
        if (StringUtils.hasText(contactInfo.telephone())) {
            if (!PHONE_PATTERN.matcher(contactInfo.telephone()).matches()) {
                throw new InvalidPatientDataException("Format de téléphone invalide: " + contactInfo.telephone());
            }
        }

        // Validation code postal si modifié
        if (StringUtils.hasText(contactInfo.codePostal())) {
            if (!CODE_POSTAL_PATTERN.matcher(contactInfo.codePostal()).matches()) {
                throw new InvalidPatientDataException("Format de code postal invalide: " + contactInfo.codePostal());
            }
        }
    }

    /**
     * Valide les modifications des consentements
     */
    private void validateConsentUpdate(
            com.lims.patient.dto.request.ConsentUpdateRequest consent,
            Patient existingPatient) {

        // Le consentement de création de compte ne peut pas être retiré
        if (consent.consentementEmail() != null || consent.consentementSms() != null) {
            if (!existingPatient.getConsentementCreationCompte()) {
                throw new ConsentValidationException(
                        "CREATION_COMPTE",
                        "Impossible de modifier les consentements sans consentement de création de compte");
            }
        }
    }

    /**
     * Valide l'unicité des données critiques
     */
    public void validateUniqueness(String numeroSecu, String email, String telephone, String excludePatientId) {
        // Vérification NIR unique
        if (StringUtils.hasText(numeroSecu)) {
            boolean nirExists = patientRepository.existsByNumeroSecuAndDateSuppressionIsNull(numeroSecu);
            if (nirExists) {
                throw new InvalidPatientDataException("Un patient avec ce numéro de sécurité sociale existe déjà");
            }
        }

        // Vérification email unique
        if (StringUtils.hasText(email)) {
            boolean emailExists = patientRepository.existsByEmailIgnoreCaseAndDateSuppressionIsNull(email);
            if (emailExists) {
                throw new InvalidPatientDataException("Un patient avec cet email existe déjà");
            }
        }

        // Vérification téléphone unique
        if (StringUtils.hasText(telephone)) {
            boolean phoneExists = patientRepository.existsByTelephoneAndDateSuppressionIsNull(telephone);
            if (phoneExists) {
                throw new InvalidPatientDataException("Un patient avec ce téléphone existe déjà");
            }
        }
    }
}