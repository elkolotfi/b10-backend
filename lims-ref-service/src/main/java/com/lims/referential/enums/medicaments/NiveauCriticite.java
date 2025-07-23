package com.lims.referential.enums.medicaments;

public enum NiveauCriticite {
    FAIBLE("Faible"),
    MODERE("Modéré"),
    ELEVE("Élevé"),
    CRITIQUE("Critique");

    private final String libelle;

    NiveauCriticite(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}