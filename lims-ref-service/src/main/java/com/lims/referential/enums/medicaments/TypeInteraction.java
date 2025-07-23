package com.lims.referential.enums.medicaments;

public enum TypeInteraction {
    INTERFERENCE("Interférence"),
    FAUX_POSITIF("Faux positif"),
    FAUX_NEGATIF("Faux négatif"),
    MODIFICATION_VALEURS("Modification des valeurs"),
    CONTRINDICATION("Contre-indication"),
    PRECAUTION("Précaution");

    private final String libelle;

    TypeInteraction(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}