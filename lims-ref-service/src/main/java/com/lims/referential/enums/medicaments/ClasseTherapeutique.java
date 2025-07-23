package com.lims.referential.enums.medicaments;

public enum ClasseTherapeutique {
    ANTALGIQUE_ANTIPYRETIQUE("Antalgique/Antipyrétique"),
    ANTI_INFLAMMATOIRE("Anti-inflammatoire"),
    ANTIBIOTIQUE("Antibiotique"),
    ANTIVIRAL("Antiviral"),
    ANTIFONGIQUE("Antifongique"),
    ANTICOAGULANT("Anticoagulant"),
    ANTIAGREGANT_PLAQUETTAIRE("Antiagrégant plaquettaire"),
    ANTIHYPERTENSEUR("Antihypertenseur"),
    DIURETIQUE("Diurétique"),
    CARDIOTONIQUE("Cardiotonique"),
    BRONCHODILATATEUR("Bronchodilatateur"),
    CORTICOIDE("Corticoïde"),
    IMMUNOSUPPRESSEUR("Immunosuppresseur"),
    ANTIDEPRESSEUR("Antidépresseur"),
    ANXIOLYTIQUE("Anxiolytique"),
    ANTICONVULSIVANT("Anticonvulsivant"),
    HYPNOTIQUE("Hypnotique"),
    ANTIDIABETIQUE("Antidiabétique"),
    HYPOLIPEMIANT("Hypolipémiant"),
    ANTIHISTAMINIQUE("Antihistaminique"),
    GASTROPROTECTEUR("Gastroprotecteur"),
    LAXATIF("Laxatif"),
    ANTIDIARRHEIQUE("Antidiarrhéique"),
    CONTRACEPTIF("Contraceptif"),
    HORMONE("Hormone"),
    VITAMINE("Vitamine"),
    MINERAL("Minéral"),
    AUTRE("Autre");

    private final String libelle;

    ClasseTherapeutique(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}