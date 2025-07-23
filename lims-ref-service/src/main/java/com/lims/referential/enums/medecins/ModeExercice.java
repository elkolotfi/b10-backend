package com.lims.referential.enums.medecins;

public enum ModeExercice {
    LIBERAL("Libéral"),
    SALARIE("Salarié"),
    MIXTE("Mixte"),
    FONCTIONNAIRE("Fonctionnaire"),
    REMPLACANT("Remplaçant");

    private final String libelle;

    ModeExercice(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}
