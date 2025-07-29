package com.lims.patient.exception;

/**
 * Exception lancée quand on tente de supprimer une assurance en cours d'utilisation.
 */
public class InsuranceInUseException extends RuntimeException {

    public InsuranceInUseException(String message) {
        super(message);
    }

    public InsuranceInUseException(String message, Throwable cause) {
        super(message, cause);
    }

    public static InsuranceInUseException cannotDelete(String insuranceId, String reason) {
        return new InsuranceInUseException(
                String.format("Impossible de supprimer l'assurance %s: %s", insuranceId, reason)
        );
    }
}