package com.lims.patient.exception;

import java.util.UUID;

/**
 * Exception lancée quand une assurance n'est pas trouvée.
 */
public class InsuranceNotFoundException extends RuntimeException {

    public InsuranceNotFoundException(String message) {
        super(message);
    }

    public InsuranceNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public InsuranceNotFoundException(UUID insuranceId, UUID patientId) {
        super(String.format("Assurance non trouvée: %s pour le patient: %s", insuranceId, patientId));
    }
}