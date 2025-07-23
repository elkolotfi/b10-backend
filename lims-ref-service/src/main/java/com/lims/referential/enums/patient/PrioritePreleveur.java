package com.lims.referential.enums.patient;

public enum PrioritePreleveur {
    NORMALE(1, "Normale"),
    PRIORITAIRE(2, "Prioritaire"),
    URGENTE(3, "Urgente");

    private final int niveau;
    private final String libelle;

    PrioritePreleveur(int niveau, String libelle) {
        this.niveau = niveau;
        this.libelle = libelle;
    }

    public int getNiveau() {
        return niveau;
    }

    public String getLibelle() {
        return libelle;
    }
}