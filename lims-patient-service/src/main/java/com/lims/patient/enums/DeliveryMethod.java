package com.lims.patient.enums;

public enum DeliveryMethod {
    EMAIL("Email"),
    SMS("SMS"),
    COURRIER("Courrier"),
    RETRAIT_PLACE("Retrait sur place"),
    TELEPHONE("Téléphone");

    private final String label;

    DeliveryMethod(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
