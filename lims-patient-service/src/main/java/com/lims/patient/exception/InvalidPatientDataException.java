package com.lims.patient.exception;

/**
 * Exception lancée quand les données du patient sont invalides
 */
public class InvalidPatientDataException extends RuntimeException {

    public InvalidPatientDataException(String message) {
        super(message);
    }

    public InvalidPatientDataException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidPatientDataException(String field, String message) {
        super(String.format("Champ '%s': %s", field, message));
    }
}