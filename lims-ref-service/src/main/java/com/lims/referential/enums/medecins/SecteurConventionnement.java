package com.lims.referential.enums.medecins;

public enum SecteurConventionnement {
    SECTEUR_1("Secteur 1 - Tarifs conventionnés"),
    SECTEUR_2("Secteur 2 - Dépassements d'honoraires autorisés"),
    SECTEUR_3("Secteur 3 - Non conventionné"),
    NON_CONVENTIONNE("Non conventionné");

    private final String description;

    SecteurConventionnement(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
