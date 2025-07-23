package com.lims;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * Application principale du service référentiel LIMS
 *
 * Responsabilités :
 * - Gestion des analyses biologiques avec codes NABM
 * - Annuaire des médecins de France avec RPPS
 * - Répertoire des laboratoires partenaires
 * - Base des médicaments avec interactions
 * - Organismes complémentaires (mutuelles)
 * - Données géographiques et codes postaux
 * - Spécificités patient impactant les prélèvements
 */
@SpringBootApplication
@EnableCaching
@EnableTransactionManagement
public class ReferentialServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(ReferentialServiceApplication.class, args);
    }
}