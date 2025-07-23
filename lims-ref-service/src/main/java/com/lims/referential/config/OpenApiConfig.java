package com.lims.referential.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Configuration OpenAPI pour le service référentiel LIMS.
 * Ce service gère les données de référence du système.
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI referentialServiceOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("LIMS Referential Service API")
                        .description("API de gestion des données de référence pour le système LIMS de laboratoire de biologie médicale. Ce service fournit les nomenclatures, tarifs, analyses disponibles et autres données de référence nécessaires au fonctionnement du LIMS.")
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("Équipe LIMS")
                                .email("support@lims.com")
                                .url("https://lims.com"))
                        .license(new License()
                                .name("Propriétaire")
                                .url("https://lims.com/license")))
                .servers(List.of(
                        new Server()
                                .url("http://localhost:8093")
                                .description("Serveur de développement"),
                        new Server()
                                .url("https://api.lims.com/referential")
                                .description("Serveur de production")))
                .addSecurityItem(new SecurityRequirement().addList("Bearer Authentication"))
                .components(new io.swagger.v3.oas.models.Components()
                        .addSecuritySchemes("Bearer Authentication",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("Token JWT admin obtenu via le service d'authentification (realm: lims-admin)")));
    }
}