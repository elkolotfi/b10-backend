package com.lims.patient.exception;

/**
 * Exception lancée quand une contrainte métier est violée
 */
public class PatientBusinessRuleException extends RuntimeException {

    public PatientBusinessRuleException(String message) {
        super(message);
    }

    public PatientBusinessRuleException(String message, Throwable cause) {
        super(message, cause);
    }

    public PatientBusinessRuleException(String rule, String violation) {
        super(String.format("Règle métier '%s' violée: %s", rule, violation));
    }
}