package com.lims.patient.mapper;

import com.lims.patient.dto.response.*;
import com.lims.patient.entity.*;
import com.lims.patient.enums.PrescriptionStatus;
import org.mapstruct.*;

import java.time.LocalDate;
import java.time.Period;
import java.util.List;
import java.util.UUID;

/**
 * Mapper principal pour convertir les entités Patient en DTOs - Version centralisée
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
    @Mapping(target = "specificities", source = ".", qualifiedByName = "toSpecificitiesResponse")
    @Mapping(target = "consent", source = ".", qualifiedByName = "toConsentResponse")
    PatientResponse toPatientResponse(Patient patient);

    /**
     * Convertit une entité Patient en PatientSummaryResponse pour les listes
     */
    @Mapping(target = "id", source = "id", qualifiedByName = "uuidToString")
    @Mapping(target = "nomComplet", source = ".", qualifiedByName = "buildFullName")
    @Mapping(target = "email", source = "email")
    @Mapping(target = "telephone", source = "telephone")
    @Mapping(target = "numeroSecuMasque", source = "numeroSecuMasque")
    @Mapping(target = "dateNaissance", source = "dateNaissance")
    @Mapping(target = "age", source = ".", qualifiedByName = "calculateAge")
    @Mapping(target = "sexe", source = "sexe")
    @Mapping(target = "ville", source = "ville")
    @Mapping(target = "statut", source = "statut")
    @Mapping(target = "dateCreation", source = "dateCreation")
    PatientSummaryResponse toPatientSummaryResponse(Patient patient);

    // ============================================
    // MAPPERS POUR SOUS-OBJETS
    // ============================================

    /**
     * Mappe les informations personnelles
     */
    @Named("toPersonalInfoResponse")
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
                .age(calculateAge(patient))
                .medecinTraitant(patient.getMedecinTraitant())
                .allergiesConnues(patient.getAllergiesConnues())
                .antecedentsMedicaux(patient.getAntecedentsMedicaux())
                .build();
    }

    /**
     * Mappe les informations de contact centralisées
     */
    @Named("toContactInfoResponse")
    default ContactInfoResponse toContactInfoResponse(Patient patient) {
        if (patient == null) return null;

        return ContactInfoResponse.builder()
                .email(patient.getEmail())
                .telephone(patient.getTelephone())
                .adresseComplete(buildAdresseComplete(patient))
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
     * Mappe les consentements
     */
    @Named("toConsentResponse")
    default ConsentResponse toConsentResponse(Patient patient) {
        if (patient == null) return null;

        return ConsentResponse.builder()
                .createAccount(patient.getConsentementCreationCompte())
                .sms(patient.getConsentementSms())
                .email(patient.getConsentementEmail())
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
                .actif(patient.isActive())
                .build();
    }

    /**
     * Convertit les spécificités du patient
     */
    @Named("toSpecificitiesResponse")
    default PatientSpecificitiesResponse toSpecificitiesResponse(Patient patient) {
        if (patient == null) return null;

        return PatientSpecificitiesResponse.builder()
                .specificityIds(patient.getSpecificityIds() != null ? patient.getSpecificityIds() : List.of())
                .build();
    }

    // ============================================
    // MAPPERS POUR ENTITÉS LIÉES (CONSERVÉES)
    // ============================================

    /**
     * Mappe les assurances
     */
    @Mapping(target = "id", source = "id", qualifiedByName = "uuidToString")
    @Mapping(target = "estActive", source = "estActive")
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
    // MÉTHODES UTILITAIRES ADAPTÉES
    // ============================================

    /**
     * Convertit UUID en String
     */
    @Named("uuidToString")
    default String uuidToString(UUID uuid) {
        return uuid != null ? uuid.toString() : null;
    }

    /**
     * Construit l'adresse complète
     */
    default String buildAdresseComplete(Patient patient) {
        if (patient == null) return null;

        StringBuilder sb = new StringBuilder();

        if (patient.getAdresseLigne1() != null) {
            sb.append(patient.getAdresseLigne1());
        }

        if (patient.getAdresseLigne2() != null && !patient.getAdresseLigne2().trim().isEmpty()) {
            sb.append(", ").append(patient.getAdresseLigne2());
        }

        if (patient.getCodePostal() != null && patient.getVille() != null) {
            sb.append(", ").append(patient.getCodePostal()).append(" ").append(patient.getVille());
        }

        if (patient.getPays() != null && !patient.getPays().equals("France")) {
            sb.append(", ").append(patient.getPays());
        }

        return sb.toString();
    }

    /**
     * Vérifie si le patient a une assurance active
     */
    @Named("hasActiveInsurance")
    default Boolean hasActiveInsurance(Patient patient) {
        if (patient == null || patient.getAssurances() == null) return false;

        return patient.getAssurances().stream()
                .anyMatch(assurance -> assurance.getEstActive() != null && assurance.getEstActive() &&
                        (assurance.getDateFin() == null || assurance.getDateFin().isAfter(LocalDate.now())));
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

    /**
     * Construit le nom complet
     */
    @Named("buildFullName")
    default String buildFullName(Patient patient) {
        if (patient == null) return null;

        StringBuilder sb = new StringBuilder();

        if (patient.getPrenom() != null) {
            sb.append(patient.getPrenom());
        }

        if (patient.getNom() != null) {
            if (sb.length() > 0) {
                sb.append(" ");
            }
            sb.append(patient.getNom());
        }

        return sb.toString();
    }

    /**
     * Vérifie si le patient est mineur
     */
    @Named("isMinor")
    default Boolean isMinor(Patient patient) {
        if (patient == null || patient.getDateNaissance() == null) return false;
        return patient.getDateNaissance().isAfter(LocalDate.now().minusYears(18));
    }

    /**
     * Calcule l'âge du patient
     */
    @Named("calculateAge")
    default Integer calculateAge(Patient patient) {
        if (patient == null || patient.getDateNaissance() == null) return 0;
        return Period.between(patient.getDateNaissance(), LocalDate.now()).getYears();
    }

    /**
     * Masque le numéro de sécurité sociale
     */
    @Named("maskNIR")
    default String maskNIR(Patient patient) {
        if (patient == null || patient.getNumeroSecu() == null) {
            return "***************";
        }

        String nir = patient.getNumeroSecu();
        if (nir.length() >= 8) {
            return nir.substring(0, 4) + "*******" + nir.substring(nir.length() - 4);
        }
        return "***************";
    }

    /**
     * Formatage du téléphone pour l'affichage
     */
    default String formatTelephone(String telephone) {
        if (telephone == null || telephone.isEmpty()) return null;

        // Supprime les espaces et caractères spéciaux
        String cleaned = telephone.replaceAll("[^0-9+]", "");

        // Format français : +33 1 23 45 67 89
        if (cleaned.startsWith("+33") && cleaned.length() == 12) {
            return cleaned.substring(0, 3) + " " +
                    cleaned.substring(3, 4) + " " +
                    cleaned.substring(4, 6) + " " +
                    cleaned.substring(6, 8) + " " +
                    cleaned.substring(8, 10) + " " +
                    cleaned.substring(10, 12);
        }

        return telephone; // Retourne tel quel si pas de format reconnu
    }

    /**
     * Validation de l'email
     */
    default Boolean isValidEmail(String email) {
        if (email == null || email.isEmpty()) return false;
        return email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    }

    /**
     * Validation du téléphone
     */
    default Boolean isValidTelephone(String telephone) {
        if (telephone == null || telephone.isEmpty()) return false;
        return telephone.matches("^\\+[1-9][0-9]{8,14}$");
    }

    /**
     * Obtient le statut de validation du patient
     */
    default String getValidationStatus(Patient patient) {
        if (patient == null) return "INVALID";

        boolean hasValidEmail = isValidEmail(patient.getEmail());
        boolean hasValidTelephone = isValidTelephone(patient.getTelephone());
        boolean hasValidAddress = patient.getAdresseLigne1() != null &&
                patient.getCodePostal() != null &&
                patient.getVille() != null;

        if (hasValidEmail && hasValidTelephone && hasValidAddress) {
            return "COMPLETE";
        } else if (hasValidEmail || hasValidTelephone) {
            return "PARTIAL";
        } else {
            return "INCOMPLETE";
        }
    }

    /**
     * Obtient une représentation courte du patient pour les logs
     */
    default String toLogString(Patient patient) {
        if (patient == null) return "Patient[null]";

        return String.format("Patient[id=%s, nom=%s, prenom=%s, email=%s]",
                patient.getId(),
                patient.getNom(),
                patient.getPrenom(),
                patient.getEmail());
    }

    /**
     * Vérifie si le patient a des notifications activées
     */
    default Boolean hasNotificationsEnabled(Patient patient) {
        if (patient == null) return false;

        return (patient.getNotificationsResultats() != null && patient.getNotificationsResultats()) ||
                (patient.getNotificationsRdv() != null && patient.getNotificationsRdv()) ||
                (patient.getNotificationsRappels() != null && patient.getNotificationsRappels());
    }

    /**
     * Obtient les types de notifications activées
     */
    default List<String> getEnabledNotificationTypes(Patient patient) {
        if (patient == null) return List.of();

        List<String> types = new java.util.ArrayList<>();

        if (patient.getNotificationsResultats() != null && patient.getNotificationsResultats()) {
            types.add("RESULTATS");
        }
        if (patient.getNotificationsRdv() != null && patient.getNotificationsRdv()) {
            types.add("RDV");
        }
        if (patient.getNotificationsRappels() != null && patient.getNotificationsRappels()) {
            types.add("RAPPELS");
        }

        return types;
    }

    /**
     * Obtient une description textuelle du statut du patient
     */
    default String getStatusDescription(Patient patient) {
        if (patient == null || patient.getStatut() == null) return "Statut inconnu";

        return switch (patient.getStatut()) {
            case ACTIF -> "Patient actif";
            case INACTIF -> "Patient inactif";
            case SUSPENDU -> "Patient suspendu";
            case DECEDE -> "Patient décédé";
            default -> "Statut inconnu";
        };
    }
}