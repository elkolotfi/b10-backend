package com.lims.patient.exception;

/**
 * Exception levée quand un patient existe déjà (doublon NIR)
 */
public class DuplicatePatientException extends RuntimeException {
    public DuplicatePatientException(String message) {
        super(message);
    }

    public DuplicatePatientException(String message, Throwable cause) {
        super(message, cause);
    }
}
