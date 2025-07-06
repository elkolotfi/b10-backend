package com.lims.patient.enums;

public enum PrescriptionStatus {
    EN_ATTENTE("En attente"),
    VALIDEE("Validée"),
    TRAITEE("Traitée"),
    EXPIREE("Expirée"),
    ANNULEE("Annulée");

    private final String label;

    PrescriptionStatus(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
