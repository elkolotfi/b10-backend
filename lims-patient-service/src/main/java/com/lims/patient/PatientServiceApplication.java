package com.lims.patient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * Application principale du service Patient LIMS
 *
 * Fonctionnalités :
 * - Gestion complète des patients (CRUD)
 * - Recherche avancée multi-critères
 * - Audit trail RGPD
 * - Sécurité avec Keycloak (realms staff et patient)
 * - Validation métier française (NIR, etc.)
 * - Cache Redis
 * - API REST documentée (OpenAPI)
 *
 * Port: 8092
 * Realm Keycloak: lims-patient (patients) + lims-staff (personnel)
 * Base de données: PostgreSQL schema lims_patient
 */
@SpringBootApplication
@EnableCaching
@EnableAsync
@EnableTransactionManagement
@EnableConfigurationProperties
public class PatientServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(PatientServiceApplication.class, args);
    }
}