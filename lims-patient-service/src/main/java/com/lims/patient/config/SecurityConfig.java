package com.lims.patient.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * Configuration de sécurité pour le service Patient LIMS
 *
 * Configuration unifiée pour tous les environnements :
 * - Supporte OAuth2 JWT avec realms lims-patient et lims-staff
 * - Endpoints publics pour les tests et health checks
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Value("${security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authz -> authz
                        // Endpoints publics (pas d'authentification)
                        .requestMatchers(
                                "/api/v1/patients/info/**",
                                "/actuator/health",
                                "/actuator/info",
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html"
                        ).permitAll()

                        // Endpoints de test (développement)
                        .requestMatchers("/api/v1/patients/me/test").hasRole("PATIENT")
                        .requestMatchers("/api/v1/patients/test/staff").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("/api/v1/patients/test/mixed").hasAnyRole("PATIENT", "STAFF", "ADMIN", "SECRETAIRE")

                        // Endpoints Staff - Gestion des patients
                        .requestMatchers("GET", "/api/v1/patients").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("POST", "/api/v1/patients").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("GET", "/api/v1/patients/{id}").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("PUT", "/api/v1/patients/{id}").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("DELETE", "/api/v1/patients/{id}").hasAnyRole("ADMIN", "SECRETAIRE")

                        // Endpoints Staff - Recherche
                        .requestMatchers("/api/v1/patients/search/**").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("/api/v1/patients/by-nir/**").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("/api/v1/patients/by-phone/**").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("/api/v1/patients/check-duplicates").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")

                        // Endpoints Staff - Assurances et ordonnances
                        .requestMatchers("/api/v1/patients/{id}/insurances/**").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("/api/v1/patients/{id}/prescriptions/**").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("/api/v1/prescriptions/**").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")

                        // Endpoints Staff - Analytics et exports (accès restreint)
                        .requestMatchers("/api/v1/patients/statistics").hasAnyRole("ADMIN", "SECRETAIRE")
                        .requestMatchers("/api/v1/patients/export").hasRole("ADMIN")
                        .requestMatchers("/api/v1/patients/rgpd-compliance").hasRole("ADMIN")
                        .requestMatchers("/api/v1/patients/batch").hasAnyRole("ADMIN", "SECRETAIRE")

                        // Endpoints Patient - Données personnelles
                        .requestMatchers("/api/v1/patients/me/**").hasRole("PATIENT")

                        // Endpoints d'intégration et webhooks
                        .requestMatchers("/api/v1/webhooks/**").permitAll() // Authentification par signature
                        .requestMatchers("/api/v1/integration/**").hasRole("ADMIN")

                        // Actuator - monitoring complet pour admin seulement
                        .requestMatchers("/actuator/**").permitAll() // En dev, tout est accessible

                        // Fallback : toute autre requête nécessite une authentification
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder())
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                );

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        return new PatientJwtAuthenticationConverter();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}