package com.lims.document.config;

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
 * Configuration OpenAPI pour la documentation Swagger du service documents.
 * Ce service gère l'upload, le téléchargement et la gestion des documents/fichiers.
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI documentServiceOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("LIMS Document Service API")
                        .description("API de gestion des documents et fichiers pour le système LIMS de laboratoire de biologie médicale. Ce service permet l'upload, le téléchargement et la gestion des documents (ordonnances, cartes mutuelles, résultats, etc.) avec stockage sécurisé sur MinIO.")
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
                                .url("http://localhost:8094")
                                .description("Serveur de développement"),
                        new Server()
                                .url("https://api.lims.com/documents")
                                .description("Serveur de production")))
                .addSecurityItem(new SecurityRequirement().addList("Bearer Authentication"))
                .components(new io.swagger.v3.oas.models.Components()
                        .addSecuritySchemes("Bearer Authentication",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("Token JWT obtenu via le service d'authentification (realm: lims-staff)")));
    }
}