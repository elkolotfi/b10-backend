package com.lims.patient.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "lims.patient.business-rules")
public class PatientBusinessProperties {
    private Integer maxContactsParType = 3;
    private Integer maxAdressesParType = 2;
    private Integer maxAssurancesParPatient = 5;
    private Boolean validationEmailObligatoire = true;
    private Boolean validationTelephoneObligatoire = false;
    private Integer dureeConservationAuditJours = 2555;
    private Boolean softDeleteUniquement = true;
}