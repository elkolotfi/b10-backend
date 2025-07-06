package com.lims.patient.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.cache.annotation.EnableCaching;

/**
 * Configuration principale du service Patient
 */
@Configuration
@EnableJpaAuditing
@EnableAsync
@EnableTransactionManagement
@EnableCaching
@RequiredArgsConstructor
public class PatientServiceConfig {

    /**
     * Configuration des propriétés métier patient
     */
    @Bean
    @ConfigurationProperties(prefix = "lims.patient.business-rules")
    public PatientBusinessProperties patientBusinessProperties() {
        return new PatientBusinessProperties();
    }

    /**
     * Configuration de l'audit
     */
    @Bean
    @ConfigurationProperties(prefix = "lims.patient.audit")
    public PatientAuditProperties patientAuditProperties() {
        return new PatientAuditProperties();
    }
}