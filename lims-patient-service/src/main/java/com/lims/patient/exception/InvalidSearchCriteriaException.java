package com.lims.patient.exception;

/**
 * Exception lancée quand les données de recherche sont invalides
 */
public class InvalidSearchCriteriaException extends RuntimeException {

    public InvalidSearchCriteriaException(String message) {
        super(message);
    }

    public InvalidSearchCriteriaException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidSearchCriteriaException(String criteria, String reason) {
        super(String.format("Critère de recherche '%s' invalide: %s", criteria, reason));
    }
}