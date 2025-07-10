package com.lims.patient.exception;

/**
 * Exception lancée quand une erreur de mapping se produit
 */
public class PatientMappingException extends RuntimeException {

    public PatientMappingException(String message) {
        super(message);
    }

    public PatientMappingException(String message, Throwable cause) {
        super(message, cause);
    }

    public PatientMappingException(String sourceType, String targetType, String reason) {
        super(String.format("Erreur de mapping de %s vers %s: %s", sourceType, targetType, reason));
    }
}