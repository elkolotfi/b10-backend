package com.lims.referential.enums.laboratoires;

public enum SpecialiteTechnique {
    BIOCHIMIE("Biochimie"),
    HEMATOLOGIE("Hématologie"),
    MICROBIOLOGIE("Microbiologie"),
    IMMUNOLOGIE("Immunologie"),
    GENETIQUE("Génétique"),
    ANATOMIE_PATHOLOGIQUE("Anatomie pathologique"),
    TOXICOLOGIE("Toxicologie"),
    RADIOLOGIE("Radiologie"),
    ECHOGRAPHIE("Échographie"),
    ENDOSCOPIE("Endoscopie"),
    CARDIOLOGIE("Cardiologie"),
    PNEUMOLOGIE("Pneumologie"),
    NEUROLOGIE("Neurologie");

    private final String libelle;

    SpecialiteTechnique(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}