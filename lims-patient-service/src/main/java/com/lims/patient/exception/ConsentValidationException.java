package com.lims.patient.exception;

/**
 * Exception lancée quand la validation des consentements RGPD échoue
 */
public class ConsentValidationException extends RuntimeException {

    public ConsentValidationException(String message) {
        super(message);
    }

    public ConsentValidationException(String message, Throwable cause) {
        super(message, cause);
    }

    public ConsentValidationException(String consentType, String reason) {
        super(String.format("Validation du consentement '%s' échoué: %s", consentType, reason));
    }
}