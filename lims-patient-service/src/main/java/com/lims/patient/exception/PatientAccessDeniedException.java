package com.lims.patient.exception;

/**
 * Exception lancée quand l'accès à un patient est refusé
 */
public class PatientAccessDeniedException extends RuntimeException {

    public PatientAccessDeniedException(String message) {
        super(message);
    }

    public PatientAccessDeniedException(String message, Throwable cause) {
        super(message, cause);
    }

    public PatientAccessDeniedException(String patientId, String userId, String reason) {
        super(String.format("Accès refusé au patient %s pour l'utilisateur %s: %s", patientId, userId, reason));
    }
}