package com.lims.laboratory.config;

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
                        .title("LIMS Laboratory Service API")  // 🔧 Changer le titre
                        .description("API de gestion des laboratoires...")  // 🔧 Changer la description
                        .version("1.0.0"))
                .servers(List.of(
                        new Server()
                                .url("http://localhost:8091")  // 🔧 Changer le port (8083 pour laboratory)
                                .description("Serveur de développement")))
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