package com.lims.patient.exception;

/**
 * Exception lancée quand un patient en doublon est détecté
 */
public class DuplicatePatientException extends RuntimeException {

    public DuplicatePatientException(String message) {
        super(message);
    }

    public DuplicatePatientException(String message, Throwable cause) {
        super(message, cause);
    }

    public DuplicatePatientException(String message, String field, String value) {
        super(String.format("%s - Champ: %s, Valeur: %s", message, field, value));
    }
}
