package com.lims.patient.service;

import com.lims.patient.dto.request.CreatePatientRequest;
import com.lims.patient.dto.request.UpdatePatientRequest;
import com.lims.patient.entity.Patient;
import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.PrescriptionStatus;
import com.lims.patient.exception.InvalidPatientDataException;
import com.lims.patient.repository.PatientRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.Period;

/**
 * Service de validation des règles métier pour les patients
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PatientValidationService {

    private final PatientRepository patientRepository;

    /**
     * Valide les données d'un nouveau patient
     */
    public void validateNewPatient(CreatePatientRequest request) {
        log.debug("Validation des données du nouveau patient");

        // Validation de l'âge (pas de nouveau-né de moins de 1 jour, pas de centenaire)
        LocalDate dateNaissance = request.personalInfo().dateNaissance();
        int age = Period.between(dateNaissance, LocalDate.now()).getYears();

        if (age < 0) {
            throw new InvalidPatientDataException("La date de naissance ne peut pas être dans le futur");
        }

        if (age > 120) {
            throw new InvalidPatientDataException("L'âge du patient semble irréaliste (plus de 120 ans)");
        }

        // Validation du NIR (format et cohérence)
        validateNIR(request.personalInfo().numeroSecu(), dateNaissance, request.personalInfo().sexe());

        // Validation des contacts principaux (au moins un contact principal par type)
        validatePrimaryContacts(request);

        // Validation des consentements obligatoires
        if (!request.consent().consentementCreationCompte()) {
            throw new InvalidPatientDataException(
                    "Le consentement pour la création de compte est obligatoire");
        }
    }

    /**
     * Valide les modifications d'un patient existant
     */
    public void validatePatientUpdate(Patient existingPatient, UpdatePatientRequest request) {
        log.debug("Validation des modifications du patient {}", existingPatient.getId());

        // Le NIR ne peut pas être modifié
        if (request.personalInfo() != null && request.personalInfo().dateNaissance() != null) {
            LocalDate newDateNaissance = request.personalInfo().dateNaissance();
            int age = Period.between(newDateNaissance, LocalDate.now()).getYears();

            if (age < 0 || age > 120) {
                throw new InvalidPatientDataException("La date de naissance n'est pas valide");
            }
        }
    }

    /**
     * Valide la suppression d'un patient
     */
    public void validatePatientDeletion(Patient patient) {
        log.debug("Validation de la suppression du patient {}", patient.getId());

        // Vérifier s'il y a des ordonnances actives
        boolean hasActivePrescriptions = patient.getOrdonnances().stream()
                .anyMatch(ordonnance -> ordonnance.getStatut() == PrescriptionStatus.EN_ATTENTE ||
                        ordonnance.getStatut() == PrescriptionStatus.VALIDEE);

        if (hasActivePrescriptions) {
            throw new InvalidPatientDataException(
                    "Impossible de supprimer le patient : il a des ordonnances actives");
        }

        // Dans un vrai système, on vérifierait aussi :
        // - Rendez-vous à venir
        // - Analyses en cours
        // - Factures impayées
    }

    /**
     * Valide le format et la cohérence du NIR
     */
    private void validateNIR(String nir, LocalDate dateNaissance, GenderType sexe) {
        if (nir == null || nir.length() != 15) {
            throw new InvalidPatientDataException("Le NIR doit contenir exactement 15 chiffres");
        }

        // Vérification du sexe (1ère chiffre : 1=homme, 2=femme)
        char firstDigit = nir.charAt(0);
        if (sexe == GenderType.M && firstDigit != '1') {
            throw new InvalidPatientDataException("NIR incohérent avec le sexe déclaré (homme)");
        }
        if (sexe == GenderType.F && firstDigit != '2') {
            throw new InvalidPatientDataException("NIR incohérent avec le sexe déclaré (femme)");
        }

        // Vérification de l'année de naissance (2 chiffres suivants)
        try {
            int yearFromNir = Integer.parseInt(nir.substring(1, 3));
            int actualYear = dateNaissance.getYear() % 100;

            if (yearFromNir != actualYear) {
                throw new InvalidPatientDataException("NIR incohérent avec la date de naissance");
            }
        } catch (NumberFormatException e) {
            throw new InvalidPatientDataException("Format NIR invalide");
        }
    }

    /**
     * Valide qu'il y a au moins un contact principal de chaque type
     */
    private void validatePrimaryContacts(CreatePatientRequest request) {
        // Au moins un téléphone principal
        boolean hasPrimaryPhone = request.contactInfo().telephones().stream()
                .anyMatch(phone -> phone.estPrincipal());

        if (!hasPrimaryPhone) {
            throw new InvalidPatientDataException("Au moins un téléphone principal est requis");
        }

        // Au moins une adresse principale
        boolean hasPrimaryAddress = request.contactInfo().adresses().stream()
                .anyMatch(address -> address.estPrincipale());

        if (!hasPrimaryAddress) {
            throw new InvalidPatientDataException("Au moins une adresse principale est requise");
        }

        // Au moins un email principal
        boolean hasPrimaryEmail = request.contactInfo().emails().stream()
                .anyMatch(email -> email.estPrincipal());

        if (!hasPrimaryEmail) {
            throw new InvalidPatientDataException("Au moins un email principal est requis");
        }
    }
}