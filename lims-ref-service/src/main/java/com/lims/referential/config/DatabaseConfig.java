package com.lims.referential.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

/**
 * Configuration de la base de données et de l'audit JPA pour le service référentiel.
 */
@Configuration
@EnableJpaRepositories(basePackages = "com.lims.referential.repository")
@EnableJpaAuditing(auditorAwareRef = "auditorProvider")
public class DatabaseConfig {

    /**
     * Auditor pour JPA Auditing - utilise l'utilisateur admin connecté
     */
    @Bean
    public AuditorAware<String> auditorProvider() {
        return () -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !authentication.isAuthenticated()) {
                return Optional.of("SYSTEM");
            }
            return Optional.of(authentication.getName());
        };
    }
}