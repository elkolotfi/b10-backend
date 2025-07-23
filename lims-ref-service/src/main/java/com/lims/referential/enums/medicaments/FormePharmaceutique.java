package com.lims.referential.enums.medicaments;

public enum FormePharmaceutique {
    COMPRIME("Comprimé"),
    GELULE("Gélule"),
    CAPSULE("Capsule"),
    SIROP("Sirop"),
    SOLUTION_BUVABLE("Solution buvable"),
    SUSPENSION_BUVABLE("Suspension buvable"),
    POUDRE("Poudre"),
    GRANULES("Granulés"),
    SACHET("Sachet"),
    AMPOULE_BUVABLE("Ampoule buvable"),
    GOUTTES("Gouttes"),
    SPRAY("Spray"),
    AEROSOL("Aérosol"),
    INHALATEUR("Inhalateur"),
    INJECTION("Injectable"),
    PERFUSION("Perfusion"),
    SUPPOSITOIRE("Suppositoire"),
    OVULE("Ovule"),
    CREME("Crème"),
    POMMADE("Pommade"),
    GEL("Gel"),
    LOTION("Lotion"),
    PATCH("Patch transdermique"),
    COLLYRE("Collyre"),
    AUTRE("Autre");

    private final String libelle;

    FormePharmaceutique(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}