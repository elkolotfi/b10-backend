package com.lims.patient.exception;

/**
 * Exception lancée quand un patient n'est pas trouvé
 */
public class PatientNotFoundException extends RuntimeException {

    public PatientNotFoundException(String message) {
        super(message);
    }

    public PatientNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public PatientNotFoundException(String message, String patientId) {
        super(String.format("%s - Patient ID: %s", message, patientId));
    }
}