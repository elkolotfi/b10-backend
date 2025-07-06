package com.lims.patient.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Contrôleur principal du service Patient
 *
 * Ce contrôleur fournira les endpoints pour :
 * - Auto-enregistrement des patients
 * - Gestion des profils patients
 * - Consultation des données personnelles
 * - Prise de rendez-vous
 */
@RestController
@RequestMapping("/api/v1/patients/info")
@Tag(name = "Patient Management", description = "API de gestion des patients LIMS")
@Slf4j
public class InfoController {

    @Value("${spring.application.name}")
    private String applicationName;

    @Value("${server.port}")
    private int serverPort;

    @Operation(
            summary = "Vérification de l'état du service",
            description = "Endpoint de health check pour le monitoring"
    )
    @GetMapping("/_health")
    public ResponseEntity<Map<String, Object>> health() {
        log.debug("Health check endpoint appelé");

        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "service", "lims-patient-service",
                "realm", "lims-patient",
                "timestamp", LocalDateTime.now(),
                "checks", Map.of(
                        "database", "UP",  // TODO: Ajouter vraie vérification DB
                        "redis", "UP",     // TODO: Ajouter vraie vérification Redis
                        "keycloak", "UP"   // TODO: Ajouter vraie vérification Keycloak
                )
        ));
    }

    @Operation(
            summary = "Informations sur l'API Patient",
            description = "Retourne les informations détaillées sur l'API et ses capacités"
    )
    @GetMapping("")
    public ResponseEntity<Map<String, Object>> info() {
        return ResponseEntity.ok(Map.of(
                "service", Map.of(
                        "name", "LIMS Patient Service",
                        "description", "Service de gestion des patients pour le système LIMS",
                        "version", "1.0.0",
                        "realm", "lims-patient",
                        "port", serverPort
                ),
                "capabilities", Map.of(
                        "patient-registration", "Auto-enregistrement avec validation email",
                        "otp-authentication", "Authentification OTP par email/SMS",
                        "profile-management", "Gestion du profil patient",
                        "appointment-booking", "Prise de rendez-vous en ligne",
                        "document-access", "Accès aux ordonnances et résultats",
                        "notification", "Notifications email/SMS"
                ),
                "security", Map.of(
                        "realm", "lims-patient",
                        "auth-method", "OAuth2 + OTP",
                        "data-encryption", true,
                        "audit-trail", true
                ),
                "api", Map.of(
                        "version", "v1",
                        "documentation", "/swagger-ui.html",
                        "openapi", "/api-docs"
                )
        ));
    }

    /**
     * Détecte le profil Spring actif
     */
    private String getActiveProfile() {
        // Cette méthode pourrait être améliorée avec @Value("${spring.profiles.active}")
        return "development"; // Par défaut
    }
}