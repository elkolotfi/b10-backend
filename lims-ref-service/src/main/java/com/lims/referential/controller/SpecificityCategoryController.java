// lims-ref-service/src/main/java/com/lims/referential/controller/SpecificityCategoryController.java
package com.lims.referential.controller;

import com.lims.referential.dto.response.SpecificityCategoryResponseDTO;
import com.lims.referential.service.SpecificityCategoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Contrôleur REST pour la gestion des catégories de spécificités patients.
 * Utilisé par le composant PatientSituation pour organiser les conditions spéciales.
 */
@RestController
@RequestMapping("/api/v1/specificity-categories")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Specificity Categories", description = "Gestion des catégories de conditions spéciales")
@SecurityRequirement(name = "Bearer Authentication")
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class SpecificityCategoryController {

    private final SpecificityCategoryService specificityCategoryService;

    /**
     * Récupère toutes les catégories actives
     * Endpoint principal pour PatientSituation
     */
    @GetMapping
    @Operation(summary = "Liste des catégories de spécificités",
            description = "Récupère toutes les catégories actives triées par ordre d'affichage")
    @ApiResponse(responseCode = "200", description = "Catégories récupérées avec succès")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<SpecificityCategoryResponseDTO>> getAllCategories() {
        log.info("GET /api/v1/specificity-categories");

        List<SpecificityCategoryResponseDTO> categories = specificityCategoryService.findAllActive();
        return ResponseEntity.ok(categories);
    }

    /**
     * Récupère une catégorie par son ID
     */
    @GetMapping("/{id}")
    @Operation(summary = "Détail d'une catégorie",
            description = "Récupère le détail d'une catégorie de spécificité par son ID")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Catégorie trouvée"),
            @ApiResponse(responseCode = "404", description = "Catégorie non trouvée")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<SpecificityCategoryResponseDTO> getCategoryById(
            @Parameter(description = "ID de la catégorie") @PathVariable String id) {

        log.info("GET /api/v1/specificity-categories/{}", id);

        SpecificityCategoryResponseDTO category = specificityCategoryService.findById(id);
        return ResponseEntity.ok(category);
    }

    /**
     * Récupère les statistiques des catégories
     */
    @GetMapping("/statistics")
    @Operation(summary = "Statistiques des catégories",
            description = "Récupère les statistiques d'utilisation des catégories")
    @ApiResponse(responseCode = "200", description = "Statistiques récupérées")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getCategoryStatistics() {
        log.info("GET /api/v1/specificity-categories/statistics");

        Map<String, Object> stats = specificityCategoryService.getStatistics();
        return ResponseEntity.ok(stats);
    }
}