package com.lims.patient.enums;

public enum GenderType {
    M("M"),
    F("F"),
    NON_PRECISE("O");

    private final String label;

    GenderType(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
