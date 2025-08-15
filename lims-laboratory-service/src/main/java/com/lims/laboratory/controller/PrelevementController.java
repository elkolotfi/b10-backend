package com.lims.laboratory.controller;

import com.lims.laboratory.dto.request.PrelevementSearchDTO;
import com.lims.laboratory.dto.response.PagedResponseDTO;
import com.lims.laboratory.dto.response.PrelevementResponseDTO;
import com.lims.laboratory.service.PrelevementService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Contrôleur REST public pour la consultation des prélèvements de laboratoire
 * Version en lecture seule pour les utilisateurs finaux
 */
@RestController
@RequestMapping("/api/v1/prelevements")
@RequiredArgsConstructor
@Slf4j
@Validated
@Tag(name = "Prélèvements (Public)", description = "Consultation des prélèvements de laboratoire")
@SecurityRequirement(name = "bearerAuth")
public class PrelevementController {

    private final PrelevementService prelevementService;

    // === CONSULTATION PUBLIQUE ===

    /**
     * Lister les prélèvements avec pagination et filtres (lecture seule)
     */
    @GetMapping
    @Operation(
            summary = "Consulter les prélèvements",
            description = "Récupère la liste paginée des prélèvements avec possibilité de filtrage (lecture seule)"
    )
    @ApiResponse(responseCode = "200", description = "Liste récupérée")
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<PagedResponseDTO<PrelevementResponseDTO>> getPrelevements(
            @Parameter(description = "Numéro de page (0-based)") @RequestParam(name = "page", defaultValue = "0") @Min(0) int page,
            @Parameter(description = "Taille de page") @RequestParam(name = "size", defaultValue = "20") @Min(1) @Max(100) int size,
            @Parameter(description = "Champ de tri") @RequestParam(name = "sort", defaultValue = "ordrePrelevement") String sortBy,
            @Parameter(description = "Direction de tri") @RequestParam(name = "dir", defaultValue = "asc") String sortDirection,
            @Parameter(description = "ID du laboratoire") @RequestParam(name = "lab") UUID laboratoireId,
            @Parameter(description = "Filtres de recherche") @ModelAttribute PrelevementSearchDTO searchDTO) {

        log.info("GET /api/v1/prelevements - page: {}, size: {}, laboratoireId: {}", page, size, laboratoireId);

        // Force le laboratoire dans les filtres
        searchDTO.setLaboratoireId(laboratoireId);

        PagedResponseDTO<PrelevementResponseDTO> response = prelevementService.getPrelevements(
                page, size, sortBy, sortDirection, searchDTO);
        return ResponseEntity.ok(response);
    }

    /**
     * Récupérer un prélèvement par son ID (lecture seule)
     */
    @GetMapping("/{id}")
    @Operation(
            summary = "Consulter un prélèvement",
            description = "Récupère les détails d'un prélèvement par son identifiant"
    )
    @ApiResponse(responseCode = "200", description = "Prélèvement trouvé")
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<PrelevementResponseDTO> getPrelevementById(@PathVariable UUID id) {
        log.info("GET /api/v1/prelevements/{}", id);

        PrelevementResponseDTO response = prelevementService.getPrelevementById(id);
        return ResponseEntity.ok(response);
    }

    /**
     * Consulter les prélèvements par laboratoire
     */
    @GetMapping("/laboratoire/{laboratoireId}")
    @Operation(
            summary = "Prélèvements par laboratoire",
            description = "Récupère tous les prélèvements d'un laboratoire spécifique"
    )
    @ApiResponse(responseCode = "200", description = "Prélèvements récupérés")
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<List<PrelevementResponseDTO>> getPrelevementsByLaboratoire(@PathVariable UUID laboratoireId) {
        log.info("GET /api/v1/prelevements/laboratoire/{}", laboratoireId);

        List<PrelevementResponseDTO> prelevements = prelevementService.getPrelevementsByLaboratoire(laboratoireId);
        return ResponseEntity.ok(prelevements);
    }

    /**
     * Consulter les prélèvements par examen
     */
    @GetMapping("/examen/{laboratoireExamenId}")
    @Operation(
            summary = "Prélèvements par examen",
            description = "Récupère tous les prélèvements d'un examen spécifique"
    )
    @ApiResponse(responseCode = "200", description = "Prélèvements récupérés")
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<List<PrelevementResponseDTO>> getPrelevementsByExamen(@PathVariable UUID laboratoireExamenId) {
        log.info("GET /api/v1/prelevements/examen/{}", laboratoireExamenId);

        List<PrelevementResponseDTO> prelevements = prelevementService.getPrelevementsByExamen(laboratoireExamenId);
        return ResponseEntity.ok(prelevements);
    }

    /**
     * Consulter les prélèvements par nature
     */
    @GetMapping("/nature/{naturePrelevementCode}")
    @Operation(
            summary = "Prélèvements par nature",
            description = "Récupère tous les prélèvements d'une nature spécifique"
    )
    @ApiResponse(responseCode = "200", description = "Prélèvements récupérés")
    @PreAuthorize("hasRole('ADMIN_LAB') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<List<PrelevementResponseDTO>> getPrelevementsByNature(@PathVariable String naturePrelevementCode) {
        log.info("GET /api/v1/prelevements/nature/{}", naturePrelevementCode);

        List<PrelevementResponseDTO> prelevements = prelevementService.getPrelevementsByNature(naturePrelevementCode);
        return ResponseEntity.ok(prelevements);
    }
}