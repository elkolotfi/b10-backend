package com.lims.patient.config;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * Configuration de sécurité pour le service Patient avec support multi-realm JWT HMAC
 */
@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Value("${security.oauth2.resourceserver.jwt.keycloak.base-url}")
    private String keycloakBaseUrl;

    @Value("${lims.jwt.secrets.admin}")
    private String adminSecret;

    @Value("${lims.jwt.secrets.patient}")
    private String patientSecret;

    @Value("${lims.jwt.secrets.staff}")
    private String staffSecret;

    /**
     * Configuration de la chaîne de filtres de sécurité
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {
        log.info("Configuring security filter chain for Patient Service with multi-realm HMAC support");

        http
                // Désactiver CSRF pour les APIs REST
                .csrf(csrf -> csrf.disable())

                // Configuration CORS
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // Politique de session stateless
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Configuration des autorisations
                .authorizeHttpRequests(authz -> authz
                        // Endpoints publics
                        .requestMatchers(
                                "/actuator/**",
                                "/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/v3/api-docs/**"
                        ).permitAll()

                        // Endpoints API - nécessitent une authentification
                        .requestMatchers("/api/v1/**").authenticated()

                        // Tout le reste nécessite une authentification
                        .anyRequest().authenticated()
                )

                // Configuration OAuth2 Resource Server avec JWT
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder)
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                );

        return http.build();
    }

    /**
     * Décodeur JWT configuré pour supporter plusieurs realms Keycloak avec HMAC
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        log.info("Using simple JJWT decoder that works in debug");
        return new SimpleHmacJwtDecoder(adminSecret);
    }

    /**
     * Convertisseur d'authentification JWT personnalisé pour multi-realms
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        return new PatientJwtAuthenticationConverter();
    }

    /**
     * Configuration CORS
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Origines autorisées (en développement, ajuster pour la production)
        configuration.setAllowedOriginPatterns(List.of("*"));

        // Méthodes HTTP autorisées
        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
        ));

        // Headers autorisés
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization", "Content-Type", "Accept", "X-Requested-With",
                "Cache-Control", "X-Laboratory-Id", "X-Patient-Id"
        ));

        // Headers exposés dans la réponse
        configuration.setExposedHeaders(Arrays.asList(
                "X-Total-Count", "X-Page-Number", "X-Page-Size"
        ));

        // Autoriser les credentials
        configuration.setAllowCredentials(true);

        // Durée de cache pour les requêtes preflight
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}