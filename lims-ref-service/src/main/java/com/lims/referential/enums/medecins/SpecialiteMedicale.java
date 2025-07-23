package com.lims.referential.enums.medecins;

public enum SpecialiteMedicale {
    MEDECINE_GENERALE("Médecine générale"),
    CARDIOLOGIE("Cardiologie"),
    DERMATOLOGIE("Dermatologie"),
    ENDOCRINOLOGIE("Endocrinologie"),
    GASTROENTEROLOGIE("Gastro-entérologie"),
    GERIATRIE("Gériatrie"),
    GYNECOLOGIE("Gynécologie"),
    HEMATOLOGIE("Hématologie"),
    NEUROLOGIE("Neurologie"),
    ONCOLOGIE("Oncologie"),
    PEDIATRIE("Pédiatrie"),
    PSYCHIATRIE("Psychiatrie"),
    RADIOLOGIE("Radiologie"),
    UROLOGIE("Urologie"),
    DIABETOLOGIE("Diabétologie"),
    NEPHROLOGIE("Néphrologie"),
    PNEUMOLOGIE("Pneumologie"),
    RHUMATOLOGIE("Rhumatologie"),
    INFECTIOLOGIE("Infectiologie"),
    AUTRE("Autre");

    private final String libelle;

    SpecialiteMedicale(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}
