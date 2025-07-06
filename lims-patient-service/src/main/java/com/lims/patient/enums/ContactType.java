package com.lims.patient.enums;


public enum ContactType {
    MOBILE("Mobile"),
    FIXE("Fixe"),
    PROFESSIONNEL("Professionnel"),
    URGENCE("Urgence");

    private final String label;

    ContactType(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
