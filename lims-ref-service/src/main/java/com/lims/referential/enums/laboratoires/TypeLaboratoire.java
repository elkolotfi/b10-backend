package com.lims.referential.enums.laboratoires;

public enum TypeLaboratoire {
    PRIVE("Laboratoire privé"),
    HOSPITALIER("Laboratoire hospitalier"),
    UNIVERSITAIRE("Laboratoire universitaire"),
    RECHERCHE("Laboratoire de recherche"),
    VETERINAIRE("Laboratoire vétérinaire"),
    INDUSTRIEL("Laboratoire industriel"),
    AUTRE("Autre");

    private final String libelle;

    TypeLaboratoire(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}