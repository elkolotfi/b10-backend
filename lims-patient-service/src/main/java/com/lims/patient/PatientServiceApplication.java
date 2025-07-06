package com.lims.patient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Application principale du service Patient LIMS
 *
 * Ce service gère :
 * - Auto-enregistrement des patients
 * - Authentification OTP (Email/SMS)
 * - Gestion des données patients
 * - Intégration avec le realm Keycloak lims-patient
 *
 * Port: 8083
 * Realm Keycloak: lims-patient
 * Base de données: lims_core.patients
 */
@SpringBootApplication
@EnableJpaAuditing
@EnableCaching
@EnableAsync
public class PatientServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(PatientServiceApplication.class, args);
    }
}