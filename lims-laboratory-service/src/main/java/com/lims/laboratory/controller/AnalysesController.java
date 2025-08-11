package com.lims.laboratory.controller;

import com.lims.laboratory.dto.request.AnalyseRequestDTO;
import com.lims.laboratory.dto.request.AnalyseSearchDTO;
import com.lims.laboratory.dto.response.AnalyseResponseDTO;
import com.lims.laboratory.dto.response.PagedResponseDTO;
import com.lims.laboratory.service.AnalyseService;
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
 * Contrôleur REST pour la gestion des analyses de laboratoire
 * Permet la personnalisation des analyses du référentiel par chaque laboratoire
 */
@RestController
@RequestMapping("/api/v1/analyses")
@RequiredArgsConstructor
@Slf4j
@Validated
@Tag(name = "Analyses", description = "Gestion des analyses personnalisées par laboratoire")
@SecurityRequirement(name = "bearerAuth")
public class AnalysesController {

    private final AnalyseService analyseService;

    // === OPÉRATIONS CRUD ===

    /**
     * Créer une nouvelle analyse personnalisée
     */
    @PostMapping
    @Operation(
            summary = "Créer une analyse",
            description = "Crée une nouvelle analyse personnalisée pour un laboratoire à partir du référentiel"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Analyse créée avec succès"),
            @ApiResponse(responseCode = "400", description = "Données invalides"),
            @ApiResponse(responseCode = "409", description = "Conflit - Analyse déjà configurée pour ce laboratoire")
    })
    @PreAuthorize("hasRole('ADMIN') or hasRole('STAFF')")
    public ResponseEntity<AnalyseResponseDTO> createAnalyse(
            @Parameter(description = "Données de l'analyse à créer")
            @Valid @RequestBody AnalyseRequestDTO requestDTO) {

        log.info("POST /api/v1/analyses - Création analyse pour laboratoire: {}", requestDTO.getLaboratoireId());

        AnalyseResponseDTO response = analyseService.createAnalyse(requestDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Modifier une analyse existante
     */
    @PutMapping("/{id}")
    @Operation(
            summary = "Modifier une analyse",
            description = "Met à jour les paramètres d'une analyse personnalisée"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Analyse modifiée avec succès"),
            @ApiResponse(responseCode = "404", description = "Analyse non trouvée"),
            @ApiResponse(responseCode = "409", description = "Conflit - Code d'analyse déjà utilisé")
    })
    @PreAuthorize("hasRole('ADMIN') or hasRole('STAFF')")
    public ResponseEntity<AnalyseResponseDTO> updateAnalyse(
            @Parameter(description = "Identifiant unique de l'analyse") @PathVariable UUID id,
            @Parameter(description = "Nouvelles données de l'analyse")
            @Valid @RequestBody AnalyseRequestDTO requestDTO) {

        log.info("PUT /api/v1/analyses/{} - Modification analyse", id);

        AnalyseResponseDTO response = analyseService.updateAnalyse(id, requestDTO);
        return ResponseEntity.ok(response);
    }

    /**
     * Supprimer une analyse
     */
    @DeleteMapping("/{id}")
    @Operation(
            summary = "Supprimer une analyse",
            description = "Supprime définitivement une analyse personnalisée du laboratoire"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Analyse supprimée avec succès"),
            @ApiResponse(responseCode = "404", description = "Analyse non trouvée")
    })
    @PreAuthorize("hasRole('ADMIN') or hasRole('STAFF')")
    public ResponseEntity<Void> deleteAnalyse(
            @Parameter(description = "Identifiant unique de l'analyse") @PathVariable UUID id) {

        log.info("DELETE /api/v1/analyses/{} - Suppression analyse", id);

        analyseService.deleteAnalyse(id);
        return ResponseEntity.noContent().build();
    }

    // === CONSULTATIONS ===

    /**
     * Récupérer une analyse par son ID
     */
    @GetMapping("/{id}")
    @Operation(
            summary = "Récupérer une analyse",
            description = "Récupère les détails d'une analyse par son identifiant"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Analyse trouvée"),
            @ApiResponse(responseCode = "404", description = "Analyse non trouvée")
    })
    @PreAuthorize("hasRole('ADMIN') or hasRole('STAFF')")
    public ResponseEntity<AnalyseResponseDTO> findById(
            @Parameter(description = "Identifiant unique de l'analyse") @PathVariable UUID id) {

        log.info("GET /api/v1/analyses/{}", id);

        AnalyseResponseDTO response = analyseService.findById(id);
        return ResponseEntity.ok(response);
    }

    /**
     * Rechercher des analyses avec critères
     */
    @GetMapping
    @Operation(
            summary = "Rechercher des analyses",
            description = "Recherche paginée des analyses avec filtres optionnels"
    )
    @ApiResponse(responseCode = "200", description = "Recherche effectuée avec succès")
    @PreAuthorize("hasRole('ADMIN') or hasRole('STAFF')")
    public ResponseEntity<PagedResponseDTO<AnalyseResponseDTO>> searchAnalyses(
            @Parameter(description = "Critères de recherche") @Valid AnalyseSearchDTO searchDTO,
            @Parameter(description = "Numéro de page (commence à 0)")
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @Parameter(description = "Taille de page")
            @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size,
            @Parameter(description = "Champ de tri")
            @RequestParam(defaultValue = "nomAnalyseLabo") String sortBy,
            @Parameter(description = "Direction du tri")
            @RequestParam(defaultValue = "ASC") String sortDirection) {

        log.info("GET /api/v1/analyses - Recherche avec critères");

        PagedResponseDTO<AnalyseResponseDTO> response = analyseService.searchAnalyses(
                searchDTO, page, size, sortBy, sortDirection);
        return ResponseEntity.ok(response);
    }

    // === ENDPOINTS SPÉCIALISÉS ===

    /**
     * Récupérer les analyses actives d'un laboratoire
     */
    @GetMapping("/laboratoire/{laboratoireId}/actives")
    @Operation(
            summary = "Analyses actives d'un laboratoire",
            description = "Récupère toutes les analyses actives configurées pour un laboratoire"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Liste des analyses actives"),
            @ApiResponse(responseCode = "404", description = "Laboratoire non trouvé")
    })
    @PreAuthorize("hasRole('ADMIN') or hasRole('STAFF')")
    public ResponseEntity<List<AnalyseResponseDTO>> findActiveAnalysesByLaboratoire(
            @Parameter(description = "Identifiant du laboratoire") @PathVariable UUID laboratoireId) {

        log.info("GET /api/v1/analyses/laboratoire/{}/actives", laboratoireId);

        List<AnalyseResponseDTO> response = analyseService.findActiveAnalysesByLaboratoire(laboratoireId);
        return ResponseEntity.ok(response);
    }

    /**
     * Récupérer les analyses d'un examen
     */
    @GetMapping("/examen/{laboratoireExamenId}")
    @Operation(
            summary = "Analyses d'un examen",
            description = "Récupère toutes les analyses actives liées à un examen de laboratoire"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Liste des analyses de l'examen"),
            @ApiResponse(responseCode = "404", description = "Examen non trouvé")
    })
    @PreAuthorize("hasRole('ADMIN') or hasRole('STAFF')")
    public ResponseEntity<List<AnalyseResponseDTO>> findAnalysesByExamen(
            @Parameter(description = "Identifiant de l'examen laboratoire") @PathVariable UUID laboratoireExamenId) {

        log.info("GET /api/v1/analyses/examen/{}", laboratoireExamenId);

        List<AnalyseResponseDTO> response = analyseService.findAnalysesByExamen(laboratoireExamenId);
        return ResponseEntity.ok(response);
    }

    // === ACTIONS SPÉCIALES ===

    /**
     * Activer/désactiver une analyse
     */
    @PatchMapping("/{id}/activation")
    @Operation(
            summary = "Activer/désactiver une analyse",
            description = "Modifie le statut actif d'une analyse sans affecter les autres données"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Statut modifié"),
            @ApiResponse(responseCode = "404", description = "Analyse non trouvée")
    })
    @PreAuthorize("hasRole('ADMIN') or hasRole('STAFF')")
    public ResponseEntity<AnalyseResponseDTO> toggleActivation(
            @Parameter(description = "Identifiant unique de l'analyse") @PathVariable UUID id,
            @Parameter(description = "Nouveau statut actif") @RequestParam boolean active) {

        log.info("PATCH /api/v1/analyses/{}/activation - Statut: {}", id, active);

        AnalyseResponseDTO response = analyseService.toggleActivation(id, active);
        return ResponseEntity.ok(response);
    }

    // === STATISTIQUES ===

    /**
     * Statistiques des analyses d'un laboratoire
     */
    @GetMapping("/laboratoire/{laboratoireId}/statistiques")
    @Operation(
            summary = "Statistiques des analyses",
            description = "Récupère des statistiques sur les analyses configurées par un laboratoire"
    )
    @ApiResponse(responseCode = "200", description = "Statistiques générées")
    @PreAuthorize("hasRole('ADMIN') or hasRole('STAFF')")
    public ResponseEntity<Map<String, Object>> getStatistiquesAnalyses(
            @Parameter(description = "Identifiant du laboratoire") @PathVariable UUID laboratoireId) {

        log.info("GET /api/v1/analyses/laboratoire/{}/statistiques", laboratoireId);

        Map<String, Object> statistiques = analyseService.getStatistiquesAnalyses(laboratoireId);
        return ResponseEntity.ok(statistiques);
    }
}