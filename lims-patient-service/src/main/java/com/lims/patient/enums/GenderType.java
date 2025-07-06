package com.lims.patient.enums;

public enum GenderType {
    M("Masculin"),
    F("Féminin"),
    NON_BINAIRE("Non binaire"),
    NON_PRECISE("Non précisé");

    private final String label;

    GenderType(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
