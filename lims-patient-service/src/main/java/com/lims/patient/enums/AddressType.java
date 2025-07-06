package com.lims.patient.enums;

public enum AddressType {
    DOMICILE("Domicile"),
    TRAVAIL("Travail"),
    FACTURATION("Facturation"),
    CORRESPONDANCE("Correspondance");

    private final String label;

    AddressType(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
