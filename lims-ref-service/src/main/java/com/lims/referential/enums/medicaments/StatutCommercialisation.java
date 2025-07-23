package com.lims.referential.enums.medicaments;

public enum StatutCommercialisation {
    COMMERCIALISE("Commercialisé"),
    ARRETE("Arrêté"),
    SUSPENDU("Suspendu"),
    RETIRE("Retiré du marché"),
    EN_COURS("En cours d'autorisation");

    private final String libelle;

    StatutCommercialisation(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}