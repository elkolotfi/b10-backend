package com.lims.referential.config;

import org.springframework.context.annotation.Configuration;

/**
 * Configuration du cache Redis avec TTL adaptés par type de données
 */
@Configuration
public class CacheConfig {

    public static final String ANALYSES_CACHE = "analyses";
    public static final String MEDECINS_CACHE = "medecins";
    public static final String LABORATOIRES_CACHE = "laboratoires";
    public static final String MEDICAMENTS_CACHE = "medicaments";
    public static final String MUTUELLES_CACHE = "mutuelles";
    public static final String GEOGRAPHIQUE_CACHE = "geographique";
    public static final String PATIENT_SPECIFICITIES_CACHE = "patient-specificities";

    // Cache TTL en secondes
    public static final int ANALYSES_TTL = 3600; // 1 heure
    public static final int MEDECINS_TTL = 7200; // 2 heures
    public static final int LABORATOIRES_TTL = 1800; // 30 minutes
    public static final int MEDICAMENTS_TTL = 3600; // 1 heure
    public static final int MUTUELLES_TTL = 7200; // 2 heures
    public static final int GEOGRAPHIQUE_TTL = 86400; // 24 heures (données stables)
    public static final int PATIENT_SPECIFICITIES_TTL = 1800; // 30 minutes
}
