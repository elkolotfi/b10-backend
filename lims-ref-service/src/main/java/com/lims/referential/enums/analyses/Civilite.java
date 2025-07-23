package com.lims.referential.enums.analyses;

public enum Civilite {
    DR("Docteur"),
    PR("Professeur"),
    M("Monsieur"),
    MME("Madame");

    private final String libelle;

    Civilite(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}
