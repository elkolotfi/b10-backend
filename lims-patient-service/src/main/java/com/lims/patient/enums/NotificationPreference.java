package com.lims.patient.enums;

public enum NotificationPreference {
    TOUS("Toutes les notifications"),
    URGENCE_UNIQUEMENT("Urgences uniquement"),
    AUCUNE("Aucune notification");

    private final String label;

    NotificationPreference(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
