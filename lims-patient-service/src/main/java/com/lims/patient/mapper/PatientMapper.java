package com.lims.patient.mapper;

import com.lims.patient.dto.response.*;
import com.lims.patient.entity.*;
import com.lims.patient.enums.PrescriptionStatus;
import org.mapstruct.*;

import java.util.List;

/**
 * Mapper principal pour convertir les entités Patient en DTOs
 * Utilise MapStruct pour la génération automatique du code
 */
@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.IGNORE,
        nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE
)
public interface PatientMapper {

    // ============================================
    // PATIENT PRINCIPAL
    // ============================================

    /**
     * Convertit une entité Patient en PatientResponse complet
     */
    @Mapping(target = "id", source = "id", qualifiedByName = "uuidToString")
    @Mapping(target = "personalInfo", source = ".", qualifiedByName = "toPersonalInfoResponse")
    @Mapping(target = "contactInfo", source = ".", qualifiedByName = "toContactInfoResponse")
    @Mapping(target = "insurances", source = "assurances")
    @Mapping(target = "ordonnances", source = "ordonnances", qualifiedByName = "toPrescriptionSummaryList")
    @Mapping(target = "consent", source = ".", qualifiedByName = "toConsentResponse")
    @Mapping(target = "metadata", source = ".", qualifiedByName = "toMetadataResponse")
    PatientResponse toPatientResponse(Patient patient);

    /**
     * Convertit une entité Patient en PatientSummaryResponse pour les listes
     */
    @Mapping(target = "id", source = "id", qualifiedByName = "uuidToString")
    @Mapping(target = "numeroSecuMasque", source = ".", qualifiedByName = "maskNIR")
    @Mapping(target = "telephonePrincipal", source = ".", qualifiedByName = "getPrimaryPhone")
    @Mapping(target = "emailPrincipal", source = ".", qualifiedByName = "getPrimaryEmail")
    @Mapping(target = "villePrincipale", source = ".", qualifiedByName = "getPrimaryCity")
    @Mapping(target = "aAssuranceActive", source = ".", qualifiedByName = "hasActiveInsurance")
    @Mapping(target = "aOrdonnanceEnCours", source = ".", qualifiedByName = "hasActivePrescription")
    PatientSummaryResponse toPatientSummaryResponse(Patient patient);

    // ============================================
    // MAPPERS POUR SOUS-OBJETS
    // ============================================

    /**
     * Mappe les informations personnelles
     */
    @Named("toPersonalInfoResponse")
    @Mapping(target = "numeroSecuMasque", source = ".", qualifiedByName = "maskNIR")
    default PersonalInfoResponse toPersonalInfoResponse(Patient patient) {
        if (patient == null) return null;

        return PersonalInfoResponse.builder()
                .nom(patient.getNom())
                .prenom(patient.getPrenom())
                .nomJeuneFille(patient.getNomJeuneFille())
                .dateNaissance(patient.getDateNaissance())
                .lieuNaissance(patient.getLieuNaissance())
                .sexe(patient.getSexe())
                .numeroSecuMasque(maskNIR(patient))
                .medecinTraitant(patient.getMedecinTraitant())
                .allergiesConnues(patient.getAllergiesConnues())
                .antecedentsMedicaux(patient.getAntecedentsMedicaux())
                .languePreferee(patient.getLanguePreferee())
                .build();
    }

    /**
     * Mappe les informations de contact
     */
    @Named("toContactInfoResponse")
    default ContactInfoResponse toContactInfoResponse(Patient patient) {
        if (patient == null) return null;

        return ContactInfoResponse.builder()
                .telephones(toPhoneContactResponseList(patient.getContacts()))
                .emails(toEmailContactResponseList(patient.getEmails()))
                .adresses(toAddressResponseList(patient.getAdresses()))
                .methodeLivraisonPreferee(patient.getMethodeLivraisonPreferee())
                .preferenceNotification(patient.getPreferenceNotification())
                .build();
    }

    /**
     * Mappe les consentements
     */
    @Named("toConsentResponse")
    default ConsentResponse toConsentResponse(Patient patient) {
        if (patient == null) return null;

        return ConsentResponse.builder()
                .consentementCreationCompte(patient.getConsentementCreationCompte())
                .consentementSms(patient.getConsentementSms())
                .consentementEmail(patient.getConsentementEmail())
                .dateConsentement(patient.getDateConsentement())
                .build();
    }

    /**
     * Mappe les métadonnées
     */
    @Named("toMetadataResponse")
    default MetadataResponse toMetadataResponse(Patient patient) {
        if (patient == null) return null;

        return MetadataResponse.builder()
                .statut(patient.getStatut())
                .dateCreation(patient.getDateCreation())
                .dateModification(patient.getDateModification())
                .creePar(patient.getCreePar())
                .modifiePar(patient.getModifiePar())
                .dateSuppression(patient.getDateSuppression())
                .build();
    }

    // ============================================
    // MAPPERS POUR ENTITÉS LIÉES
    // ============================================

    /**
     * Mappe les contacts téléphoniques
     */
    @Mapping(target = "id", source = "id", qualifiedByName = "uuidToString")
    PhoneContactResponse toPhoneContactResponse(PatientContact contact);

    List<PhoneContactResponse> toPhoneContactResponseList(List<PatientContact> contacts);

    /**
     * Mappe les adresses
     */
    @Mapping(target = "id", source = "id", qualifiedByName = "uuidToString")
    AddressResponse toAddressResponse(PatientAddress address);

    List<AddressResponse> toAddressResponseList(List<PatientAddress> addresses);

    /**
     * Mappe les emails
     */
    @Mapping(target = "id", source = "id", qualifiedByName = "uuidToString")
    EmailContactResponse toEmailContactResponse(PatientEmail email);

    List<EmailContactResponse> toEmailContactResponseList(List<PatientEmail> emails);

    /**
     * Mappe les assurances
     */
    @Mapping(target = "id", source = "id", qualifiedByName = "uuidToString")
    InsuranceResponse toInsuranceResponse(PatientAssurance assurance);

    List<InsuranceResponse> toInsuranceResponseList(List<PatientAssurance> assurances);

    /**
     * Mappe les ordonnances en résumé
     */
    @Named("toPrescriptionSummaryList")
    default List<PrescriptionSummaryResponse> toPrescriptionSummaryList(List<Ordonnance> ordonnances) {
        if (ordonnances == null) return List.of();

        return ordonnances.stream()
                .filter(o -> o.getDateSuppression() == null) // Exclut les supprimées
                .map(this::toPrescriptionSummaryResponse)
                .toList();
    }

    @Mapping(target = "id", source = "id", qualifiedByName = "uuidToString")
    @Mapping(target = "nombreAnalyses", source = "analyses", qualifiedByName = "countAnalyses")
    PrescriptionSummaryResponse toPrescriptionSummaryResponse(Ordonnance ordonnance);

    // ============================================
    // MÉTHODES UTILITAIRES
    // ============================================

    /**
     * Convertit UUID en String
     */
    @Named("uuidToString")
    default String uuidToString(java.util.UUID uuid) {
        return uuid != null ? uuid.toString() : null;
    }

    /**
     * Masque le NIR pour la sécurité
     */
    @Named("maskNIR")
    default String maskNIR(Patient patient) {
        if (patient == null || patient.getNumeroSecu() == null) {
            return "***************";
        }
        return patient.getNumeroSecuMasque();
    }

    /**
     * Récupère le téléphone principal
     */
    @Named("getPrimaryPhone")
    default String getPrimaryPhone(Patient patient) {
        if (patient == null || patient.getContacts() == null) return null;

        return patient.getContacts().stream()
                .filter(PatientContact::getEstPrincipal)
                .findFirst()
                .map(PatientContact::getNumeroTelephone)
                .orElse(null);
    }

    /**
     * Récupère l'email principal
     */
    @Named("getPrimaryEmail")
    default String getPrimaryEmail(Patient patient) {
        if (patient == null || patient.getEmails() == null) return null;

        return patient.getEmails().stream()
                .filter(PatientEmail::getEstPrincipal)
                .findFirst()
                .map(PatientEmail::getAdresseEmail)
                .orElse(null);
    }

    /**
     * Récupère la ville principale
     */
    @Named("getPrimaryCity")
    default String getPrimaryCity(Patient patient) {
        if (patient == null || patient.getAdresses() == null) return null;

        return patient.getAdresses().stream()
                .filter(PatientAddress::getEstPrincipale)
                .findFirst()
                .map(PatientAddress::getVille)
                .orElse(null);
    }

    /**
     * Vérifie si le patient a une assurance active
     */
    @Named("hasActiveInsurance")
    default Boolean hasActiveInsurance(Patient patient) {
        if (patient == null || patient.getAssurances() == null) return false;

        return patient.getAssurances().stream()
                .anyMatch(PatientAssurance::isCurrentlyValid);
    }

    /**
     * Vérifie si le patient a une ordonnance en cours
     */
    @Named("hasActivePrescription")
    default Boolean hasActivePrescription(Patient patient) {
        if (patient == null || patient.getOrdonnances() == null) return false;

        return patient.getOrdonnances().stream()
                .anyMatch(o -> o.getDateSuppression() == null &&
                        (o.getStatut() == PrescriptionStatus.EN_ATTENTE ||
                                o.getStatut() == PrescriptionStatus.VALIDEE));
    }

    /**
     * Compte le nombre d'analyses dans une ordonnance
     */
    @Named("countAnalyses")
    default Integer countAnalyses(List<OrdonnanceAnalyse> analyses) {
        return analyses != null ? analyses.size() : 0;
    }
}

// ============================================
// MAPPER POUR AUDIT
// ============================================



// ============================================
// CONFIGURATION MAPPER
// ============================================



// ============================================
// ENTITÉ AUDIT LOG (MANQUANTE)
// ============================================



// ============================================
// DTO AUDIT RESPONSE (MANQUANT)
// ============================================



// ============================================
// EXCEPTIONS PERSONNALISÉES
// ============================================







// ============================================
// GLOBAL EXCEPTION HANDLER
// ============================================

