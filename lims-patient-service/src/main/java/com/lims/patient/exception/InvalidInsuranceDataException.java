package com.lims.patient.exception;

/**
 * Exception lancée pour les données d'assurance invalides.
 * Notamment utilisée pour valider le document justificatif obligatoire.
 */
public class InvalidInsuranceDataException extends RuntimeException {

    public InvalidInsuranceDataException(String message) {
        super(message);
    }

    public InvalidInsuranceDataException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Exception spécifique pour document manquant.
     */
    public static InvalidInsuranceDataException missingDocument() {
        return new InvalidInsuranceDataException(
                "Le document justificatif est obligatoire pour créer une assurance. " +
                        "Veuillez scanner ou uploader la carte de mutuelle du patient."
        );
    }

    /**
     * Exception spécifique pour données invalides avec détail.
     */
    public static InvalidInsuranceDataException invalidField(String field, String reason) {
        return new InvalidInsuranceDataException(
                String.format("Donnée invalide pour le champ '%s': %s", field, reason)
        );
    }
}