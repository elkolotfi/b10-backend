package com.lims.laboratory.controller;

import com.lims.laboratory.dto.request.PrelevementRequestDTO;
import com.lims.laboratory.dto.request.PrelevementSearchDTO;
import com.lims.laboratory.dto.response.PagedResponseDTO;
import com.lims.laboratory.dto.response.PrelevementResponseDTO;
import com.lims.laboratory.service.PrelevementService;
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
 * Contrôleur REST pour la gestion des prélèvements de laboratoire
 * Permet aux administrateurs de laboratoire de gérer leurs prélèvements personnalisés
 */
@RestController
@RequestMapping("/api/v1/admin/prelevements")
@RequiredArgsConstructor
@Slf4j
@Validated
@Tag(name = "Prélèvements", description = "Gestion des prélèvements de laboratoire")
@SecurityRequirement(name = "bearerAuth")
public class AdminPrelevementController {

    private final PrelevementService prelevementService;

    // === OPÉRATIONS CRUD ===

    /**
     * Créer un nouveau prélèvement pour un examen
     */
    @PostMapping
    @Operation(
            summary = "Créer un prélèvement",
            description = "Ajoute un nouveau prélèvement personnalisé pour un examen de laboratoire"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Prélèvement créé avec succès"),
            @ApiResponse(responseCode = "400", description = "Données invalides"),
            @ApiResponse(responseCode = "409", description = "Ordre de prélèvement déjà existant pour cet examen")
    })
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE')")
    public ResponseEntity<PrelevementResponseDTO> createPrelevement(@Valid @RequestBody PrelevementRequestDTO requestDTO) {
        log.info("POST /api/v1/admin/prelevements - Création prélèvement pour examen: {}", requestDTO.getLaboratoireExamenId());

        PrelevementResponseDTO response = prelevementService.createPrelevement(requestDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Lister les prélèvements avec pagination et filtres
     */
    @GetMapping
    @Operation(
            summary = "Lister les prélèvements",
            description = "Récupère la liste paginée des prélèvements avec possibilité de filtrage"
    )
    @ApiResponse(responseCode = "200", description = "Liste récupérée")
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<PagedResponseDTO<PrelevementResponseDTO>> getPrelevements(
            @Parameter(description = "Numéro de page (0-based)") @RequestParam(name = "page", defaultValue = "0") @Min(0) int page,
            @Parameter(description = "Taille de page") @RequestParam(name = "size", defaultValue = "20") @Min(1) @Max(100) int size,
            @Parameter(description = "Champ de tri") @RequestParam(name = "sort", defaultValue = "ordrePrelevement") String sortBy,
            @Parameter(description = "Direction de tri") @RequestParam(name = "dir", defaultValue = "asc") String sortDirection,
            @Parameter(description = "Filtres de recherche") @ModelAttribute PrelevementSearchDTO searchDTO) {

        log.info("GET /api/v1/admin/prelevements - page: {}, size: {}", page, size);

        PagedResponseDTO<PrelevementResponseDTO> response = prelevementService.getPrelevements(
                page, size, sortBy, sortDirection, searchDTO);
        return ResponseEntity.ok(response);
    }

    /**
     * Récupérer un prélèvement par son ID
     */
    @GetMapping("/{id}")
    @Operation(
            summary = "Récupérer un prélèvement",
            description = "Récupère les détails d'un prélèvement par son identifiant"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Prélèvement trouvé"),
            @ApiResponse(responseCode = "404", description = "Prélèvement non trouvé")
    })
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<PrelevementResponseDTO> getPrelevementById(@PathVariable UUID id) {
        log.info("GET /api/v1/admin/prelevements/{}", id);

        PrelevementResponseDTO response = prelevementService.getPrelevementById(id);
        return ResponseEntity.ok(response);
    }

    /**
     * Mettre à jour un prélèvement existant
     */
    @PutMapping("/{id}")
    @Operation(
            summary = "Modifier un prélèvement",
            description = "Met à jour les informations d'un prélèvement existant"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Prélèvement mis à jour"),
            @ApiResponse(responseCode = "404", description = "Prélèvement non trouvé"),
            @ApiResponse(responseCode = "400", description = "Données invalides")
    })
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE')")
    public ResponseEntity<PrelevementResponseDTO> updatePrelevement(
            @PathVariable UUID id,
            @Valid @RequestBody PrelevementRequestDTO requestDTO) {
        log.info("PUT /api/v1/admin/prelevements/{}", id);

        PrelevementResponseDTO response = prelevementService.updatePrelevement(id, requestDTO);
        return ResponseEntity.ok(response);
    }

    /**
     * Supprimer un prélèvement
     */
    @DeleteMapping("/{id}")
    @Operation(
            summary = "Supprimer un prélèvement",
            description = "Supprime définitivement un prélèvement"
    )
    @ApiResponse(responseCode = "204", description = "Prélèvement supprimé")
    @PreAuthorize("hasRole('ADMIN_LAB')")
    public ResponseEntity<Void> deletePrelevement(@PathVariable UUID id) {
        log.info("DELETE /api/v1/admin/prelevements/{}", id);

        prelevementService.deletePrelevement(id);
        return ResponseEntity.noContent().build();
    }

    // === RECHERCHES SPÉCIALISÉES ===

    /**
     * Rechercher des prélèvements par laboratoire
     */
    @GetMapping("/laboratoire/{laboratoireId}")
    @Operation(
            summary = "Prélèvements par laboratoire",
            description = "Récupère tous les prélèvements d'un laboratoire spécifique"
    )
    @ApiResponse(responseCode = "200", description = "Prélèvements récupérés")
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<List<PrelevementResponseDTO>> getPrelevementsByLaboratoire(@PathVariable UUID laboratoireId) {
        log.info("GET /api/v1/admin/prelevements/laboratoire/{}", laboratoireId);

        List<PrelevementResponseDTO> prelevements = prelevementService.getPrelevementsByLaboratoire(laboratoireId);
        return ResponseEntity.ok(prelevements);
    }

    /**
     * Rechercher des prélèvements par examen
     */
    @GetMapping("/examen/{laboratoireExamenId}")
    @Operation(
            summary = "Prélèvements par examen",
            description = "Récupère tous les prélèvements d'un examen spécifique"
    )
    @ApiResponse(responseCode = "200", description = "Prélèvements récupérés")
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<List<PrelevementResponseDTO>> getPrelevementsByExamen(@PathVariable UUID laboratoireExamenId) {
        log.info("GET /api/v1/admin/prelevements/examen/{}", laboratoireExamenId);

        List<PrelevementResponseDTO> prelevements = prelevementService.getPrelevementsByExamen(laboratoireExamenId);
        return ResponseEntity.ok(prelevements);
    }

    /**
     * Rechercher des prélèvements par nature
     */
    @GetMapping("/nature/{naturePrelevementCode}")
    @Operation(
            summary = "Prélèvements par nature",
            description = "Récupère tous les prélèvements d'une nature spécifique"
    )
    @ApiResponse(responseCode = "200", description = "Prélèvements récupérés")
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE')")
    public ResponseEntity<List<PrelevementResponseDTO>> getPrelevementsByNature(@PathVariable String naturePrelevementCode) {
        log.info("GET /api/v1/admin/prelevements/nature/{}", naturePrelevementCode);

        List<PrelevementResponseDTO> prelevements = prelevementService.getPrelevementsByNature(naturePrelevementCode);
        return ResponseEntity.ok(prelevements);
    }

    // === ACTIONS SPÉCIALES ===

    /**
     * Réorganiser l'ordre des prélèvements d'un examen
     */
    @PutMapping("/examen/{laboratoireExamenId}/reorder")
    @Operation(
            summary = "Réorganiser les prélèvements",
            description = "Change l'ordre des prélèvements d'un examen"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Ordre mis à jour"),
            @ApiResponse(responseCode = "400", description = "Liste invalide")
    })
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE')")
    public ResponseEntity<List<PrelevementResponseDTO>> reorderPrelevements(
            @PathVariable UUID laboratoireExamenId,
            @RequestBody List<UUID> prelevementIds) {
        log.info("PUT /api/v1/admin/prelevements/examen/{}/reorder", laboratoireExamenId);

        List<PrelevementResponseDTO> response = prelevementService.reorderPrelevements(laboratoireExamenId, prelevementIds);
        return ResponseEntity.ok(response);
    }

    /**
     * Dupliquer les prélèvements d'un examen vers un autre
     */
    @PostMapping("/examen/{sourceExamenId}/duplicate/{targetExamenId}")
    @Operation(
            summary = "Dupliquer les prélèvements",
            description = "Copie tous les prélèvements d'un examen vers un autre examen"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Prélèvements dupliqués"),
            @ApiResponse(responseCode = "404", description = "Examen source ou cible non trouvé")
    })
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE')")
    public ResponseEntity<List<PrelevementResponseDTO>> duplicatePrelevements(
            @PathVariable UUID sourceExamenId,
            @PathVariable UUID targetExamenId) {
        log.info("POST /api/v1/admin/prelevements/examen/{}/duplicate/{}", sourceExamenId, targetExamenId);

        List<PrelevementResponseDTO> response = prelevementService.duplicatePrelevements(sourceExamenId, targetExamenId);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // === STATISTIQUES ===

    /**
     * Obtenir les statistiques des prélèvements d'un laboratoire
     */
    /**
     * Obtenir les statistiques des prélèvements d'un laboratoire
     */
    @GetMapping("/laboratoire/{laboratoireId}/statistiques")
    @Operation(
            summary = "Statistiques des prélèvements",
            description = "Récupère les statistiques détaillées des prélèvements d'un laboratoire"
    )
    @ApiResponse(responseCode = "200", description = "Statistiques récupérées")
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE')")
    public ResponseEntity<Map<String, Object>> getStatistiquesPrelevements(@PathVariable UUID laboratoireId) {
        log.info("GET /api/v1/admin/prelevements/laboratoire/{}/statistiques", laboratoireId);

        Map<String, Object> statistiques = prelevementService.getStatistiquesPrelevements(laboratoireId);
        return ResponseEntity.ok(statistiques);
    }
}