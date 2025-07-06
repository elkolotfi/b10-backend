package com.lims.patient.exception;

/**
 * Exception levée quand un patient n'est pas trouvé
 */
public class PatientNotFoundException extends RuntimeException {
    public PatientNotFoundException(String message) {
        super(message);
    }

    public PatientNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}