package com.lims.patient.service;

import com.lims.patient.dto.request.*;
import com.lims.patient.dto.response.*;
import com.lims.patient.entity.*;
import com.lims.patient.enums.PatientStatus;
import com.lims.patient.exception.*;
import com.lims.patient.mapper.PatientMapper;
import com.lims.patient.repository.*;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.List;
import java.util.Optional;

/**
 * Service principal pour la gestion des patients
 * Gère les opérations CRUD et la logique métier
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class PatientService {

    private final PatientRepository patientRepository;
    private final PatientContactRepository contactRepository;
    private final PatientAddressRepository addressRepository;
    private final PatientEmailRepository emailRepository;
    private final PatientAssuranceRepository assuranceRepository;
    private final PatientMapper patientMapper;
    private final PatientValidationService validationService;
    private final PatientAuditService auditService;

    /**
     * Crée un nouveau patient avec toutes ses informations
     */
    public PatientResponse createPatient(CreatePatientRequest request) {
        log.info("Création d'un nouveau patient: {} {}",
                request.personalInfo().prenom(), request.personalInfo().nom());

        // 1. Validation métier
        validationService.validateNewPatient(request);

        // 2. Vérification de l'unicité du NIR
        if (patientRepository.existsByNumeroSecuAndDateSuppressionIsNull(
                request.personalInfo().numeroSecu())) {
            throw new DuplicatePatientException(
                    "Un patient avec ce numéro de sécurité sociale existe déjà");
        }

        // 3. Création de l'entité patient principal
        Patient patient = Patient.builder()
                .nom(request.personalInfo().nom().toUpperCase())
                .prenom(request.personalInfo().prenom())
                .nomJeuneFille(request.personalInfo().nomJeuneFille())
                .dateNaissance(request.personalInfo().dateNaissance())
                .lieuNaissance(request.personalInfo().lieuNaissance())
                .sexe(request.personalInfo().sexe())
                .numeroSecu(request.personalInfo().numeroSecu())
                .medecinTraitant(request.personalInfo().medecinTraitant())
                .allergiesConnues(request.personalInfo().allergiesConnues())
                .antecedentsMedicaux(request.personalInfo().antecedentsMedicaux())
                .languePreferee(request.personalInfo().languePreferee())
                .methodeLivraisonPreferee(request.contactInfo().methodeLivraisonPreferee())
                .preferenceNotification(request.contactInfo().preferenceNotification())
                .consentementCreationCompte(request.consent().consentementCreationCompte())
                .consentementSms(request.consent().consentementSms())
                .consentementEmail(request.consent().consentementEmail())
                .dateConsentement(LocalDateTime.now())
                .creePar(request.createdBy())
                .build();

        // 4. Sauvegarde du patient principal
        patient = patientRepository.save(patient);
        log.info("Patient principal créé avec l'ID: {}", patient.getId());

        // 5. Ajout des contacts téléphoniques
        if (request.contactInfo().telephones() != null) {
            for (PhoneContactRequest phoneRequest : request.contactInfo().telephones()) {
                PatientContact contact = PatientContact.builder()
                        .patient(patient)
                        .typeContact(phoneRequest.typeContact())
                        .numeroTelephone(phoneRequest.numeroTelephone())
                        .indicatifPays(phoneRequest.indicatifPays())
                        .extension(phoneRequest.extension())
                        .estPrincipal(phoneRequest.estPrincipal())
                        .nomContactUrgence(phoneRequest.nomContactUrgence())
                        .relationContact(phoneRequest.relationContact())
                        .build();

                patient.addContact(contact);
            }
        }

        // 6. Ajout des adresses
        if (request.contactInfo().adresses() != null) {
            for (AddressRequest addressRequest : request.contactInfo().adresses()) {
                PatientAddress address = PatientAddress.builder()
                        .patient(patient)
                        .typeAdresse(addressRequest.typeAdresse())
                        .ligne1(addressRequest.ligne1())
                        .ligne2(addressRequest.ligne2())
                        .codePostal(addressRequest.codePostal())
                        .ville(addressRequest.ville())
                        .departement(addressRequest.departement())
                        .region(addressRequest.region())
                        .pays(addressRequest.pays())
                        .estPrincipale(addressRequest.estPrincipale())
                        .build();

                patient.addAdresse(address);
            }
        }

        // 7. Ajout des emails
        if (request.contactInfo().emails() != null) {
            for (EmailContactRequest emailRequest : request.contactInfo().emails()) {
                PatientEmail email = PatientEmail.builder()
                        .patient(patient)
                        .adresseEmail(emailRequest.adresseEmail())
                        .estPrincipal(emailRequest.estPrincipal())
                        .notificationsResultats(emailRequest.notificationsResultats())
                        .notificationsRdv(emailRequest.notificationsRdv())
                        .notificationsRappels(emailRequest.notificationsRappels())
                        .build();

                patient.addEmail(email);
            }
        }

        // 8. Ajout des assurances
        if (request.insurances() != null) {
            for (InsuranceRequest insuranceRequest : request.insurances()) {
                PatientAssurance assurance = PatientAssurance.builder()
                        .patient(patient)
                        .typeAssurance(insuranceRequest.typeAssurance())
                        .nomOrganisme(insuranceRequest.nomOrganisme())
                        .numeroAdherent(insuranceRequest.numeroAdherent())
                        .dateDebut(insuranceRequest.dateDebut())
                        .dateFin(insuranceRequest.dateFin())
                        .tiersPayantAutorise(insuranceRequest.tiersPayantAutorise())
                        .pourcentagePriseCharge(insuranceRequest.pourcentagePriseCharge())
                        .referenceDocument(insuranceRequest.referenceDocument())
                        .build();

                patient.addAssurance(assurance);
            }
        }

        // 9. Sauvegarde finale avec toutes les relations
        patient = patientRepository.save(patient);

        // 10. Audit de la création
        auditService.logPatientCreation(patient, request.createdBy());

        log.info("Patient créé avec succès - ID: {} - {} contacts, {} adresses, {} emails, {} assurances",
                patient.getId(),
                patient.getContacts().size(),
                patient.getAdresses().size(),
                patient.getEmails().size(),
                patient.getAssurances().size());

        // 11. Conversion en DTO de réponse
        return patientMapper.toPatientResponse(patient);
    }

    /**
     * Récupère un patient par son ID
     */
    @Transactional(readOnly = true)
    public PatientResponse getPatientById(UUID id) {
        log.info("Récupération du patient avec l'ID: {}", id);

        Patient patient = patientRepository.findByIdAndDateSuppressionIsNull(id)
                .orElseThrow(() -> new PatientNotFoundException("Patient non trouvé avec l'ID: " + id));

        return patientMapper.toPatientResponse(patient);
    }

    /**
     * Met à jour un patient existant (mise à jour partielle)
     */
    public PatientResponse updatePatient(UUID id, UpdatePatientRequest request) {
        log.info("Mise à jour du patient avec l'ID: {}", id);

        // 1. Récupération du patient existant
        Patient patient = patientRepository.findByIdAndDateSuppressionIsNull(id)
                .orElseThrow(() -> new PatientNotFoundException("Patient non trouvé avec l'ID: " + id));

        // 2. Validation des modifications
        validationService.validatePatientUpdate(patient, request);

        // 3. Mise à jour des informations personnelles
        if (request.personalInfo() != null) {
            updatePersonalInfo(patient, request.personalInfo());
        }

        // 4. Mise à jour des informations de contact
        if (request.contactInfo() != null) {
            updateContactInfo(patient, request.contactInfo());
        }

        // 5. Mise à jour des consentements
        if (request.consent() != null) {
            updateConsent(patient, request.consent());
        }

        // 6. Mise à jour des métadonnées
        patient.setModifiePar(request.modifiedBy());
        patient.setDateModification(LocalDateTime.now());

        // 7. Sauvegarde
        patient = patientRepository.save(patient);

        // 8. Audit de la modification
        auditService.logPatientUpdate(patient, request.modifiedBy());

        log.info("Patient mis à jour avec succès - ID: {}", id);

        return patientMapper.toPatientResponse(patient);
    }

    /**
     * Supprime un patient (soft delete)
     */
    public void deletePatient(UUID id, String deletedBy) {
        log.warn("Suppression du patient avec l'ID: {} par: {}", id, deletedBy);

        // 1. Récupération du patient existant
        Patient patient = patientRepository.findByIdAndDateSuppressionIsNull(id)
                .orElseThrow(() -> new PatientNotFoundException("Patient non trouvé avec l'ID: " + id));

        // 2. Vérification des contraintes métier avant suppression
        validationService.validatePatientDeletion(patient);

        // 3. Soft delete du patient
        patient.setDateSuppression(LocalDateTime.now());
        patient.setModifiePar(deletedBy);
        patient.setStatut(PatientStatus.INACTIF);

        patientRepository.save(patient);

        // 4. Audit de la suppression
        auditService.logPatientDeletion(patient, deletedBy);

        log.warn("Patient supprimé avec succès (soft delete) - ID: {}", id);
    }

    /**
     * Vérifie si un utilisateur patient est propriétaire de ses données
     */
    @Transactional(readOnly = true)
    public boolean isPatientOwner(String userEmail, UUID patientId) {
        // Dans un vrai système, il faudrait faire le lien avec Keycloak
        // Ici on vérifie si l'email de l'utilisateur correspond à un email du patient
        return emailRepository.existsByPatientIdAndAdresseEmail(patientId, userEmail);
    }

    /**
     * Met à jour les informations personnelles du patient
     */
    private void updatePersonalInfo(Patient patient, PersonalInfoUpdateRequest personalInfo) {
        if (personalInfo.nom() != null) {
            patient.setNom(personalInfo.nom().toUpperCase());
        }
        if (personalInfo.prenom() != null) {
            patient.setPrenom(personalInfo.prenom());
        }
        if (personalInfo.nomJeuneFille() != null) {
            patient.setNomJeuneFille(personalInfo.nomJeuneFille());
        }
        if (personalInfo.dateNaissance() != null) {
            patient.setDateNaissance(personalInfo.dateNaissance());
        }
        if (personalInfo.lieuNaissance() != null) {
            patient.setLieuNaissance(personalInfo.lieuNaissance());
        }
        if (personalInfo.sexe() != null) {
            patient.setSexe(personalInfo.sexe());
        }
        if (personalInfo.medecinTraitant() != null) {
            patient.setMedecinTraitant(personalInfo.medecinTraitant());
        }
        if (personalInfo.allergiesConnues() != null) {
            patient.setAllergiesConnues(personalInfo.allergiesConnues());
        }
        if (personalInfo.antecedentsMedicaux() != null) {
            patient.setAntecedentsMedicaux(personalInfo.antecedentsMedicaux());
        }
        if (personalInfo.languePreferee() != null) {
            patient.setLanguePreferee(personalInfo.languePreferee());
        }
    }

    /**
     * Met à jour les informations de contact du patient
     */
    private void updateContactInfo(Patient patient, ContactInfoUpdateRequest contactInfo) {
        // Mise à jour des préférences
        if (contactInfo.methodeLivraisonPreferee() != null) {
            patient.setMethodeLivraisonPreferee(contactInfo.methodeLivraisonPreferee());
        }
        if (contactInfo.preferenceNotification() != null) {
            patient.setPreferenceNotification(contactInfo.preferenceNotification());
        }

        // Mise à jour des contacts téléphoniques
        if (contactInfo.telephones() != null) {
            // Suppression des anciens contacts
            contactRepository.deleteByPatient(patient);
            patient.getContacts().clear();

            // Ajout des nouveaux contacts
            for (PhoneContactRequest phoneRequest : contactInfo.telephones()) {
                PatientContact contact = PatientContact.builder()
                        .patient(patient)
                        .typeContact(phoneRequest.typeContact())
                        .numeroTelephone(phoneRequest.numeroTelephone())
                        .indicatifPays(phoneRequest.indicatifPays())
                        .extension(phoneRequest.extension())
                        .estPrincipal(phoneRequest.estPrincipal())
                        .nomContactUrgence(phoneRequest.nomContactUrgence())
                        .relationContact(phoneRequest.relationContact())
                        .build();

                patient.addContact(contact);
            }
        }

        // Mise à jour des adresses
        if (contactInfo.adresses() != null) {
            // Suppression des anciennes adresses
            addressRepository.deleteByPatient(patient);
            patient.getAdresses().clear();

            // Ajout des nouvelles adresses
            for (AddressRequest addressRequest : contactInfo.adresses()) {
                PatientAddress address = PatientAddress.builder()
                        .patient(patient)
                        .typeAdresse(addressRequest.typeAdresse())
                        .ligne1(addressRequest.ligne1())
                        .ligne2(addressRequest.ligne2())
                        .codePostal(addressRequest.codePostal())
                        .ville(addressRequest.ville())
                        .departement(addressRequest.departement())
                        .region(addressRequest.region())
                        .pays(addressRequest.pays())
                        .estPrincipale(addressRequest.estPrincipale())
                        .build();

                patient.addAdresse(address);
            }
        }

        // Mise à jour des emails
        if (contactInfo.emails() != null) {
            // Suppression des anciens emails
            emailRepository.deleteByPatient(patient);
            patient.getEmails().clear();

            // Ajout des nouveaux emails
            for (EmailContactRequest emailRequest : contactInfo.emails()) {
                PatientEmail email = PatientEmail.builder()
                        .patient(patient)
                        .adresseEmail(emailRequest.adresseEmail())
                        .estPrincipal(emailRequest.estPrincipal())
                        .notificationsResultats(emailRequest.notificationsResultats())
                        .notificationsRdv(emailRequest.notificationsRdv())
                        .notificationsRappels(emailRequest.notificationsRappels())
                        .build();

                patient.addEmail(email);
            }
        }
    }

    /**
     * Met à jour les consentements du patient
     */
    private void updateConsent(Patient patient, ConsentUpdateRequest consent) {
        if (consent.consentementSms() != null) {
            patient.setConsentementSms(consent.consentementSms());
        }
        if (consent.consentementEmail() != null) {
            patient.setConsentementEmail(consent.consentementEmail());
        }
    }
}
