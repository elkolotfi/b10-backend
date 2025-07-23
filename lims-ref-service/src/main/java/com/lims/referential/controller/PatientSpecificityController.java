// lims-ref-service/src/main/java/com/lims/referential/controller/PatientSpecificityController.java
package com.lims.referential.controller;

import com.lims.referential.dto.common.PagedResponseDTO;
import com.lims.referential.dto.request.PatientSpecificityRequestDTO;
import com.lims.referential.dto.response.PatientSpecificityResponseDTO;
import com.lims.referential.service.PatientSpecificityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Contrôleur REST pour la gestion des spécificités patients.
 * Utilisé par le composant PatientSituation du frontend.
 */
@RestController
@RequestMapping("/api/v1/patient-specificities")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Patient Specificities", description = "Gestion des conditions spéciales des patients")
@SecurityRequirement(name = "Bearer Authentication")
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class PatientSpecificityController {

    private final PatientSpecificityService patientSpecificityService;

    // ============================================
    // ENDPOINTS POUR LE COMPOSANT PatientSituation
    // ============================================

    /**
     * Récupère toutes les spécificités actives groupées par catégorie
     * Endpoint principal utilisé par PatientSituation
     */
    @GetMapping("/grouped-by-category")
    @Operation(summary = "Spécificités groupées par catégorie",
            description = "Récupère toutes les spécificités actives organisées par catégorie pour le composant PatientSituation")
    @ApiResponse(responseCode = "200", description = "Spécificités récupérées avec succès")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getSpecificitiesGroupedByCategory() {
        log.info("GET /api/v1/patient-specificities/grouped-by-category");

        Map<String, Object> result = patientSpecificityService.getSpecificitiesGroupedByCategory();
        return ResponseEntity.ok(result);
    }

    /**
     * Récupère toutes les catégories actives avec leurs spécificités
     */
    @GetMapping("/categories-with-specificities")
    @Operation(summary = "Catégories avec spécificités",
            description = "Récupère les catégories actives avec leurs spécificités associées")
    @ApiResponse(responseCode = "200", description = "Catégories récupérées avec succès")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<Map<String, Object>>> getCategoriesWithSpecificities() {
        log.info("GET /api/v1/patient-specificities/categories-with-specificities");

        List<Map<String, Object>> categories = patientSpecificityService.getCategoriesWithSpecificities();
        return ResponseEntity.ok(categories);
    }

    /**
     * Recherche de spécificités par catégorie
     */
    @GetMapping("/by-category/{categoryId}")
    @Operation(summary = "Spécificités par catégorie",
            description = "Récupère les spécificités d'une catégorie donnée")
    @ApiResponse(responseCode = "200", description = "Spécificités récupérées")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PagedResponseDTO<PatientSpecificityResponseDTO>> getSpecificitiesByCategory(
            @Parameter(description = "ID de la catégorie") @PathVariable String categoryId,
            @PageableDefault(size = 50, sort = "prioritePreleveur", direction = Sort.Direction.DESC) Pageable pageable) {

        log.info("GET /api/v1/patient-specificities/by-category/{}", categoryId);

        PagedResponseDTO<PatientSpecificityResponseDTO> result =
                patientSpecificityService.findByCategory(categoryId, pageable);
        return ResponseEntity.ok(result);
    }

    // ============================================
    // ENDPOINTS STANDARD CRUD
    // ============================================

    /**
     * Récupère toutes les spécificités avec pagination
     */
    @GetMapping
    @Operation(summary = "Liste des spécificités patients",
            description = "Récupère toutes les spécificités patients avec pagination")
    @ApiResponse(responseCode = "200", description = "Liste récupérée avec succès")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PagedResponseDTO<PatientSpecificityResponseDTO>> getAllSpecificities(
            @PageableDefault(size = 20, sort = "prioritePreleveur", direction = Sort.Direction.DESC) Pageable pageable) {

        log.info("GET /api/v1/patient-specificities - page: {}, size: {}",
                pageable.getPageNumber(), pageable.getPageSize());

        PagedResponseDTO<PatientSpecificityResponseDTO> result = patientSpecificityService.findAll(pageable);
        return ResponseEntity.ok(result);
    }

    /**
     * Récupère une spécificité par son ID
     */
    @GetMapping("/{id}")
    @Operation(summary = "Détail d'une spécificité",
            description = "Récupère le détail d'une spécificité patient par son ID")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Spécificité trouvée"),
            @ApiResponse(responseCode = "404", description = "Spécificité non trouvée")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientSpecificityResponseDTO> getSpecificityById(
            @Parameter(description = "ID de la spécificité") @PathVariable UUID id) {

        log.info("GET /api/v1/patient-specificities/{}", id);

        PatientSpecificityResponseDTO result = patientSpecificityService.findById(id);
        return ResponseEntity.ok(result);
    }

    /**
     * Recherche avec filtres
     */
    @GetMapping("/search")
    @Operation(summary = "Recherche avec filtres",
            description = "Recherche de spécificités avec filtres par catégorie, niveau d'alerte, etc.")
    @ApiResponse(responseCode = "200", description = "Résultats de recherche")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PagedResponseDTO<PatientSpecificityResponseDTO>> searchSpecificities(
            @Parameter(description = "ID de la catégorie") @RequestParam(required = false) String categorie,
            @Parameter(description = "Niveau d'alerte") @RequestParam(required = false) String niveauAlerte,
            @Parameter(description = "Statut actif") @RequestParam(required = false) Boolean actif,
            @Parameter(description = "Terme de recherche") @RequestParam(required = false) String search,
            @PageableDefault(size = 20, sort = "prioritePreleveur", direction = Sort.Direction.DESC) Pageable pageable) {

        log.info("GET /api/v1/patient-specificities/search - catégorie: {}, niveau: {}, actif: {}, search: {}",
                categorie, niveauAlerte, actif, search);

        PagedResponseDTO<PatientSpecificityResponseDTO> result =
                patientSpecificityService.findWithFilters(categorie, niveauAlerte, actif, pageable);
        return ResponseEntity.ok(result);
    }

    // ============================================
    // ENDPOINTS D'ADMINISTRATION (Admin seulement)
    // ============================================

    /**
     * Crée une nouvelle spécificité
     */
    @PostMapping
    @Operation(summary = "Créer une spécificité",
            description = "Crée une nouvelle spécificité patient")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Spécificité créée avec succès"),
            @ApiResponse(responseCode = "400", description = "Données invalides")
    })
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<PatientSpecificityResponseDTO> createSpecificity(
            @Valid @RequestBody PatientSpecificityRequestDTO requestDTO) {

        log.info("POST /api/v1/patient-specificities - création: {}", requestDTO.getTitre());

        PatientSpecificityResponseDTO result = patientSpecificityService.create(requestDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    /**
     * Met à jour une spécificité existante
     */
    @PutMapping("/{id}")
    @Operation(summary = "Mettre à jour une spécificité",
            description = "Met à jour une spécificité patient existante")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Spécificité mise à jour"),
            @ApiResponse(responseCode = "404", description = "Spécificité non trouvée"),
            @ApiResponse(responseCode = "400", description = "Données invalides")
    })
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<PatientSpecificityResponseDTO> updateSpecificity(
            @Parameter(description = "ID de la spécificité") @PathVariable UUID id,
            @Valid @RequestBody PatientSpecificityRequestDTO requestDTO) {

        log.info("PUT /api/v1/patient-specificities/{} - mise à jour: {}", id, requestDTO.getTitre());

        PatientSpecificityResponseDTO result = patientSpecificityService.update(id, requestDTO);
        return ResponseEntity.ok(result);
    }

    /**
     * Supprime une spécificité
     */
    @DeleteMapping("/{id}")
    @Operation(summary = "Supprimer une spécificité",
            description = "Supprime une spécificité patient (soft delete)")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Spécificité supprimée"),
            @ApiResponse(responseCode = "404", description = "Spécificité non trouvée")
    })
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteSpecificity(
            @Parameter(description = "ID de la spécificité") @PathVariable UUID id) {

        log.info("DELETE /api/v1/patient-specificities/{}", id);

        patientSpecificityService.delete(id);
        return ResponseEntity.noContent().build();
    }

    /**
     * Statistiques sur les spécificités
     */
    @GetMapping("/statistics")
    @Operation(summary = "Statistiques des spécificités",
            description = "Récupère les statistiques sur l'utilisation des spécificités")
    @ApiResponse(responseCode = "200", description = "Statistiques récupérées")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getStatistics() {
        log.info("GET /api/v1/patient-specificities/statistics");

        Map<String, Object> stats = patientSpecificityService.getStatistics();
        return ResponseEntity.ok(stats);
    }
}