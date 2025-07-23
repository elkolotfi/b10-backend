package com.lims.referential.enums.mutuelles;

public enum TypeOrganisme {
    CPAM("Caisse Primaire d'Assurance Maladie"),
    MUTUELLE("Mutuelle"),
    ASSURANCE("Compagnie d'assurance"),
    CMUC("Couverture Maladie Universelle Complémentaire"),
    INSTITUTION_PREVOYANCE("Institution de prévoyance"),
    AUTRE("Autre");

    private final String libelle;

    TypeOrganisme(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}