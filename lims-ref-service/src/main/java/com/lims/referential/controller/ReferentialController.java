// lims-ref-service/src/main/java/com/lims/referential/controller/ReferentialController.java
package com.lims.referential.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Contrôleur de test pour valider l'authentification admin dans le service référentiel.
 */
@RestController
@RequestMapping("/api/v1/referential")
@Tag(name = "Referential", description = "Gestion des données de référence du LIMS")
@SecurityRequirement(name = "Bearer Authentication")
@Slf4j
public class ReferentialController {

    @GetMapping("/health")
    @Operation(summary = "Test de santé du service référentiel",
            description = "Vérifie que le service est opérationnel et que l'authentification admin fonctionne")
    @ApiResponse(responseCode = "200", description = "Service opérationnel")
    @ApiResponse(responseCode = "401", description = "Token JWT invalide ou manquant")
    @ApiResponse(responseCode = "403", description = "Utilisateur non autorisé (admin requis)")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> health(Authentication authentication) {
        log.info("Health check accessed by admin: {}", authentication.getName());

        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "lims-ref-service");
        response.put("timestamp", System.currentTimeMillis());
        response.put("user", authentication.getName());

        // Si c'est un JWT, extraire quelques infos utiles
        if (authentication.getPrincipal() instanceof Jwt jwt) {
            response.put("realm", jwt.getClaimAsString("realm"));
            response.put("userType", jwt.getClaimAsString("user_type"));
            response.put("expiresAt", jwt.getExpiresAt());
        }

        return ResponseEntity.ok(response);
    }

    @GetMapping("/analyses")
    @Operation(summary = "Liste des analyses disponibles",
            description = "Retourne la liste des analyses de biologie médicale disponibles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<Map<String, Object>>> getAnalyses() {
        log.info("Fetching analyses list");

        // Exemple de données de référence (à remplacer par une vraie base)
        List<Map<String, Object>> analyses = List.of(
                Map.of("code", "BIO001", "nom", "Numération Formule Sanguine", "prix", 25.50),
                Map.of("code", "BIO002", "nom", "Glycémie à jeun", "prix", 15.30),
                Map.of("code", "BIO003", "nom", "Cholestérol total", "prix", 18.20),
                Map.of("code", "BIO004", "nom", "Créatininémie", "prix", 12.00)
        );

        return ResponseEntity.ok(analyses);
    }

    @GetMapping("/laboratoires")
    @Operation(summary = "Liste des laboratoires partenaires",
            description = "Retourne la liste des laboratoires référencés dans le système")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<Map<String, Object>>> getLaboratoires() {
        log.info("Fetching laboratories list");

        // Exemple de données (à remplacer par une vraie base)
        List<Map<String, Object>> laboratoires = List.of(
                Map.of("id", "LAB001", "nom", "Laboratoire Central Paris", "ville", "Paris", "actif", true),
                Map.of("id", "LAB002", "nom", "Biolab Lyon", "ville", "Lyon", "actif", true),
                Map.of("id", "LAB003", "nom", "Lab Provence", "ville", "Marseille", "actif", false)
        );

        return ResponseEntity.ok(laboratoires);
    }

    @PostMapping("/analyses")
    @Operation(summary = "Créer une nouvelle analyse",
            description = "Ajoute une nouvelle analyse au référentiel")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> createAnalyse(@RequestBody Map<String, Object> analyse) {
        log.info("Creating new analyse: {}", analyse);

        // Validation basique
        if (!analyse.containsKey("code") || !analyse.containsKey("nom")) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Code et nom sont obligatoires"));
        }

        // Ici on sauvegarderait en base
        log.info("Analyse créée avec succès: {}", analyse.get("code"));

        return ResponseEntity.ok(Map.of("message", "Analyse créée avec succès"));
    }

    @GetMapping("/admin-info")
    @Operation(summary = "Informations sur l'admin connecté",
            description = "Retourne les détails de l'administrateur connecté")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getAdminInfo(Authentication authentication) {
        log.info("Admin info requested by: {}", authentication.getName());

        Map<String, Object> adminInfo = new HashMap<>();
        adminInfo.put("username", authentication.getName());
        adminInfo.put("authorities", authentication.getAuthorities());

        if (authentication.getPrincipal() instanceof Jwt jwt) {
            adminInfo.put("realm", jwt.getClaimAsString("realm"));
            adminInfo.put("userType", jwt.getClaimAsString("user_type"));
            adminInfo.put("subject", jwt.getSubject());
            adminInfo.put("issuedAt", jwt.getIssuedAt());
            adminInfo.put("expiresAt", jwt.getExpiresAt());

            // Claims spécifiques aux admins
            adminInfo.put("permissions", jwt.getClaimAsStringList("permissions"));
            adminInfo.put("adminLevel", jwt.getClaimAsString("admin_level"));
        }

        return ResponseEntity.ok(adminInfo);
    }
}