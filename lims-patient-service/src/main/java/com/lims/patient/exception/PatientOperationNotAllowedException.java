package com.lims.patient.exception;

/**
 * Exception lancée quand une opération sur un patient n'est pas autorisée
 */
public class PatientOperationNotAllowedException extends RuntimeException {

    public PatientOperationNotAllowedException(String message) {
        super(message);
    }

    public PatientOperationNotAllowedException(String message, Throwable cause) {
        super(message, cause);
    }

    public PatientOperationNotAllowedException(String operation, String reason) {
        super(String.format("Opération '%s' non autorisée: %s", operation, reason));
    }
}
