package com.lims.patient.enums;

public enum PatientStatus {
    ACTIF("Actif"),
    INACTIF("Inactif"),
    SUSPENDU("Suspendu"),
    DECEDE("Décédé");

    private final String label;

    PatientStatus(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
