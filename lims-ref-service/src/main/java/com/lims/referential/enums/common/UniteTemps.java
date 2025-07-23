package com.lims.referential.enums.common;

public enum UniteTemps {
    MINUTES("Minutes"),
    HEURES("Heures"),
    JOURS("Jours"),
    SEMAINES("Semaines"),
    MOIS("Mois"),
    ANNEES("Années");

    private final String libelle;

    UniteTemps(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}