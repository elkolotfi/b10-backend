package com.lims.referential.enums.patient;

public enum NiveauAlerte {
    NORMAL("Normal"),
    WARNING("Attention"),
    CRITICAL("Critique");

    private final String libelle;

    NiveauAlerte(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}