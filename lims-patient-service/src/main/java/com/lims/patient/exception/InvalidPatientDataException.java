package com.lims.patient.exception;

/**
 * Exception levée pour des données patient invalides
 */
public class InvalidPatientDataException extends RuntimeException {
    public InvalidPatientDataException(String message) {
        super(message);
    }

    public InvalidPatientDataException(String message, Throwable cause) {
        super(message, cause);
    }
}
