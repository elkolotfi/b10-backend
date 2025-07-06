package com.lims.patient.enums;

public enum InsuranceType {
    PRIMAIRE("Assurance primaire (Sécurité Sociale)"),
    COMPLEMENTAIRE("Assurance complémentaire (Mutuelle)"),
    SPECIAL("Régime spécial (CMU-C, ACS, AME)");

    private final String label;

    InsuranceType(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
