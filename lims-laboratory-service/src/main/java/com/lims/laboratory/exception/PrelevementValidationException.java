package com.lims.laboratory.exception;

/**
 * Exception levée lors d'erreurs de validation des prélèvements
 */
public class PrelevementValidationException extends RuntimeException {

    public PrelevementValidationException(String message) {
        super(message);
    }

    public PrelevementValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}