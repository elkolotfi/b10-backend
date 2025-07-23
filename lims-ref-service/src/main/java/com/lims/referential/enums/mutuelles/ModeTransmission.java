package com.lims.referential.enums.mutuelles;

public enum ModeTransmission {
    NOEMIE("Noémie"),
    EDIFACT("EDIFACT"),
    PAPIER("Papier"),
    B2B("B2B"),
    API("API"),
    EMAIL("Email"),
    AUTRE("Autre");

    private final String libelle;

    ModeTransmission(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}