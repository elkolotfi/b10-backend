package com.lims.laboratory.controller;

import com.lims.laboratory.dto.request.ExamenRequestDTO;
import com.lims.laboratory.dto.request.ExamenSearchDTO;
import com.lims.laboratory.dto.response.ExamenResponseDTO;
import com.lims.laboratory.dto.response.PagedResponseDTO;
import com.lims.laboratory.service.ExamenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Contrôleur REST pour la gestion des examens de laboratoire
 * Permet aux administrateurs de laboratoire de gérer leurs examens personnalisés
 */
@RestController
@RequestMapping("/api/v1/examens")
@RequiredArgsConstructor
@Slf4j
@Validated
@Tag(name = "Examens", description = "Gestion des examens de laboratoire")
@SecurityRequirement(name = "bearerAuth")
public class ExamenController {

    private final ExamenService examenService;

    // === Opérations CRUD ===
    /**
     * Lister les examens avec pagination et filtres
     */
    @GetMapping
    @Operation(
            summary = "Lister les examens",
            description = "Récupère la liste paginée des examens avec possibilité de filtrage"
    )
    @ApiResponse(responseCode = "200", description = "Liste récupérée")
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<PagedResponseDTO<ExamenResponseDTO>> getExamens(
            @Parameter(description = "Numéro de page (0-based)") @RequestParam(name = "page", defaultValue = "0") @Min(0) int page,
            @Parameter(description = "Taille de page") @RequestParam(name = "size", defaultValue = "20") @Min(1) @Max(100) int size,
            @Parameter(description = "Champ de tri") @RequestParam(name = "sort", defaultValue = "nomExamenLabo") String sortBy,
            @Parameter(description = "Direction de tri") @RequestParam(name = "dir", defaultValue = "asc") String sortDirection,
            @Parameter(description = "ID du laboratoire") @RequestParam(name = "lab") UUID laboratoireId,
            @Parameter(description = "Filtres de recherche") @ModelAttribute ExamenSearchDTO searchDTO) {

        log.info("GET /api/v1/examens - page: {}, size: {}, laboratoireId: {}", page, size, laboratoireId);

        searchDTO.setExamenActif(true);

        PagedResponseDTO<ExamenResponseDTO> response = examenService.getExamens(
                page, size, sortBy, sortDirection, laboratoireId, searchDTO);
        return ResponseEntity.ok(response);
    }

    /**
     * Obtenir un examen par son ID
     */
    @GetMapping("/{id}")
    @Operation(
            summary = "Obtenir un examen",
            description = "Récupère les détails complets d'un examen spécifique"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Examen trouvé"),
            @ApiResponse(responseCode = "404", description = "Examen non trouvé")
    })
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<ExamenResponseDTO> getExamenById(@PathVariable(name = "id") UUID id) {
        log.info("GET /api/v1/examens/{}", id);

        ExamenResponseDTO response = examenService.getActifExamenById(id);
        return ResponseEntity.ok(response);
    }

    /**
     * Mettre à jour un examen
     */
    @PutMapping("/{id}")
    @Operation(
            summary = "Modifier un examen",
            description = "Met à jour les informations d'un examen existant"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Examen modifié"),
            @ApiResponse(responseCode = "404", description = "Examen non trouvé"),
            @ApiResponse(responseCode = "400", description = "Données invalides")
    })
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE')")
    public ResponseEntity<ExamenResponseDTO> updateExamen(
            @PathVariable UUID id,
            @Valid @RequestBody ExamenRequestDTO requestDTO) {

        log.info("PUT /api/v1/examens/{}", id);

        ExamenResponseDTO response = examenService.updateExamen(id, requestDTO);
        return ResponseEntity.ok(response);
    }

    /**
     * Supprimer (désactiver) un examen
     */
    @DeleteMapping("/{id}")
    @Operation(
            summary = "Supprimer un examen",
            description = "Désactive un examen (soft delete) - l'examen reste accessible pour l'historique"
    )
    @ApiResponse(responseCode = "204", description = "Examen supprimé")
    @PreAuthorize("hasRole('ADMIN_LAB')")
    public ResponseEntity<Void> deleteExamen(@PathVariable UUID id) {
        log.info("DELETE /api/v1/examens/{}", id);

        examenService.deleteExamen(id);
        return ResponseEntity.noContent().build();
    }

    // === Recherches spécialisées ===

    /**
     * Rechercher des examens par laboratoire
     */
    @GetMapping("/laboratoire/{laboratoireId}")
    @Operation(
            summary = "Examens par laboratoire",
            description = "Récupère tous les examens actifs d'un laboratoire spécifique"
    )
    @ApiResponse(responseCode = "200", description = "Examens récupérés")
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<List<ExamenResponseDTO>> getExamensByLaboratoire(@PathVariable UUID laboratoireId) {
        log.info("GET /api/v1/examens/laboratoire/{}", laboratoireId);

        List<ExamenResponseDTO> examens = examenService.getExamensByLaboratoire(laboratoireId);
        return ResponseEntity.ok(examens);
    }

    /**
     * Rechercher des examens par code référentiel
     */
    @GetMapping("/referentiel/{examenReferentielId}")
    @Operation(
            summary = "Examens par référentiel",
            description = "Trouve tous les laboratoires proposant un examen du référentiel"
    )
    @ApiResponse(responseCode = "200", description = "Examens trouvés")
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE')")
    public ResponseEntity<List<ExamenResponseDTO>> getExamensByReferentiel(@PathVariable UUID examenReferentielId) {
        log.info("GET /api/v1/examens/referentiel/{}", examenReferentielId);

        List<ExamenResponseDTO> examens = examenService.getExamensByReferentiel(examenReferentielId);
        return ResponseEntity.ok(examens);
    }

    // === Actions spécialisées ===

    /**
     * Activer/désactiver un examen
     */
    @PatchMapping("/{id}/activation")
    @Operation(
            summary = "Activer/désactiver un examen",
            description = "Change le statut actif d'un examen sans affecter les autres données"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Statut modifié"),
            @ApiResponse(responseCode = "404", description = "Examen non trouvé")
    })
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE')")
    public ResponseEntity<ExamenResponseDTO> toggleActivation(
            @PathVariable UUID id,
            @RequestParam boolean actif) {

        log.info("PATCH /api/v1/examens/{}/activation - Statut: {}", id, actif);

        ExamenResponseDTO response = examenService.toggleActivation(id, actif);
        return ResponseEntity.ok(response);
    }

    /**
     * Dupliquer un examen vers un autre laboratoire
     */
    @PostMapping("/{id}/dupliquer")
    @Operation(
            summary = "Dupliquer un examen",
            description = "Copie un examen existant vers un ou plusieurs autres laboratoires"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Examens dupliqués"),
            @ApiResponse(responseCode = "404", description = "Examen source non trouvé"),
            @ApiResponse(responseCode = "400", description = "Laboratoires cibles invalides")
    })
    @PreAuthorize("hasRole('ADMIN_LAB')")
    public ResponseEntity<List<ExamenResponseDTO>> dupliquerExamen(
            @PathVariable UUID id,
            @RequestParam List<UUID> laboratoireIds) {

        log.info("POST /api/v1/examens/{}/dupliquer vers {} laboratoires", id, laboratoireIds.size());

        List<ExamenResponseDTO> examens = examenService.dupliquerExamen(id, laboratoireIds);
        return ResponseEntity.status(HttpStatus.CREATED).body(examens);
    }

    // === Statistiques ===

    /**
     * Statistiques des examens
     */
    @GetMapping("/statistiques")
    @Operation(
            summary = "Statistiques des examens",
            description = "Récupère des statistiques sur les examens du laboratoire"
    )
    @ApiResponse(responseCode = "200", description = "Statistiques générées")
    @PreAuthorize("hasRole('ADMIN_LAB')")
    public ResponseEntity<Map<String, Object>> getStatistiques(
            @RequestParam(required = false) UUID laboratoireId) {
        log.info("GET /api/v1/examens/statistiques - laboratoireId: {}", laboratoireId);

        Map<String, Object> statistiques = examenService.getStatistiques(laboratoireId);
        return ResponseEntity.ok(statistiques);
    }
}