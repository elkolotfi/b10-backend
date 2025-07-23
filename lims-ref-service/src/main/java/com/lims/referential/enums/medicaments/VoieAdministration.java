package com.lims.referential.enums.medicaments;

public enum VoieAdministration {
    ORALE("Orale"),
    INTRAVEINEUSE("Intraveineuse"),
    INTRAMUSCULAIRE("Intramusculaire"),
    SOUS_CUTANEE("Sous-cutanée"),
    INTRADERMIQUE("Intradermique"),
    TOPIQUE("Topique"),
    RECTALE("Rectale"),
    VAGINALE("Vaginale"),
    OCULAIRE("Oculaire"),
    NASALE("Nasale"),
    INHALEE("Inhalée"),
    SUBLINGUALE("Sublinguale"),
    TRANSDERMIQUE("Transdermique"),
    AUTRE("Autre");

    private final String libelle;

    VoieAdministration(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}