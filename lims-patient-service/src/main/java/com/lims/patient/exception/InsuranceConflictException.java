package com.lims.patient.exception;

/**
 * Exception lancée en cas de conflit d'assurance (ex: même type déjà actif).
 */
public class InsuranceConflictException extends RuntimeException {

    public InsuranceConflictException(String message) {
        super(message);
    }

    public InsuranceConflictException(String message, Throwable cause) {
        super(message, cause);
    }

    public InsuranceConflictException(String insuranceType, String patientId) {
        super(String.format("Conflit d'assurance: Le patient %s possède déjà une assurance active de type %s",
                patientId, insuranceType));
    }
}