package com.lims.laboratory.controller;

import com.lims.laboratory.dto.request.LaboratoireRequestDTO;
import com.lims.laboratory.dto.request.LaboratoireSearchDTO;
import com.lims.laboratory.dto.response.LaboratoireResponseDTO;
import com.lims.laboratory.dto.response.PagedResponseDTO;
import com.lims.laboratory.entity.Laboratoire.TypeLaboratoire;
import com.lims.laboratory.service.LaboratoireService;
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
 * Contrôleur REST pour la gestion des laboratoires
 * Permet aux administrateurs de créer, modifier, supprimer et consulter les laboratoires
 */
@RestController
@RequestMapping("/api/v1/laboratoires")
@RequiredArgsConstructor
@Slf4j
@Validated
@Tag(name = "Laboratoires", description = "Gestion des laboratoires")
@SecurityRequirement(name = "bearerAuth")
public class LaboratoireController {

    private final LaboratoireService laboratoireService;

    // === Opérations CRUD ===

    /**
     * Créer un nouveau laboratoire
     */
    @PostMapping
    @Operation(
            summary = "Créer un laboratoire",
            description = "Crée un nouveau laboratoire dans le système. Accessible aux administrateurs uniquement."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Laboratoire créé avec succès"),
            @ApiResponse(responseCode = "400", description = "Données invalides"),
            @ApiResponse(responseCode = "409", description = "Conflit - Données dupliquées (SIRET, FINESS, etc.)"),
            @ApiResponse(responseCode = "403", description = "Accès refusé - Droits administrateur requis")
    })
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<LaboratoireResponseDTO> createLaboratoire(
            @Valid @RequestBody LaboratoireRequestDTO requestDTO) {

        log.info("POST /api/v1/laboratoires - Création d'un laboratoire: {}", requestDTO.getNomCommercial());

        LaboratoireResponseDTO response = laboratoireService.createLaboratoire(requestDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Récupérer un laboratoire par ID
     */
    @GetMapping("/{id}")
    @Operation(
            summary = "Récupérer un laboratoire",
            description = "Récupère les détails d'un laboratoire par son identifiant"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Laboratoire trouvé"),
            @ApiResponse(responseCode = "404", description = "Laboratoire non trouvé"),
            @ApiResponse(responseCode = "403", description = "Accès refusé")
    })
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<LaboratoireResponseDTO> getLaboratoireById(
            @Parameter(description = "Identifiant unique du laboratoire") @PathVariable(name = "id") UUID id) {

        log.info("GET /api/v1/laboratoires/{}", id);

        LaboratoireResponseDTO response = laboratoireService.getLaboratoireById(id);
        return ResponseEntity.ok(response);
    }

    /**
     * Mettre à jour un laboratoire
     */
    @PutMapping("/{id}")
    @Operation(
            summary = "Mettre à jour un laboratoire",
            description = "Met à jour les informations d'un laboratoire existant"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Laboratoire mis à jour"),
            @ApiResponse(responseCode = "400", description = "Données invalides"),
            @ApiResponse(responseCode = "404", description = "Laboratoire non trouvé"),
            @ApiResponse(responseCode = "409", description = "Conflit - Données dupliquées"),
            @ApiResponse(responseCode = "403", description = "Accès refusé")
    })
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<LaboratoireResponseDTO> updateLaboratoire(
            @Parameter(description = "Identifiant unique du laboratoire") @PathVariable UUID id,
            @Valid @RequestBody LaboratoireRequestDTO requestDTO) {

        log.info("PUT /api/v1/laboratoires/{} - Mise à jour: {}", id, requestDTO.getNomCommercial());

        LaboratoireResponseDTO response = laboratoireService.updateLaboratoire(id, requestDTO);
        return ResponseEntity.ok(response);
    }

    /**
     * Supprimer un laboratoire
     */
    @DeleteMapping("/{id}")
    @Operation(
            summary = "Supprimer un laboratoire",
            description = "Supprime définitivement un laboratoire du système"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Laboratoire supprimé"),
            @ApiResponse(responseCode = "404", description = "Laboratoire non trouvé"),
            @ApiResponse(responseCode = "403", description = "Accès refusé")
    })
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteLaboratoire(
            @Parameter(description = "Identifiant unique du laboratoire") @PathVariable UUID id) {

        log.info("DELETE /api/v1/laboratoires/{}", id);

        laboratoireService.deleteLaboratoire(id);
        return ResponseEntity.noContent().build();
    }

    // === Recherche et listage ===

    /**
     * Rechercher des laboratoires avec critères et pagination
     */
    @GetMapping
    @Operation(
            summary = "Rechercher des laboratoires",
            description = "Recherche paginée de laboratoires avec différents critères de filtrage"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Résultats de recherche"),
            @ApiResponse(responseCode = "400", description = "Paramètres de pagination invalides")
    })
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<PagedResponseDTO<LaboratoireResponseDTO>> searchLaboratoires(
            @Parameter(description = "Terme de recherche (nom, code)") @RequestParam(required = false) String searchTerm,
            @Parameter(description = "Type de laboratoire") @RequestParam(required = false) TypeLaboratoire typeLaboratoire,
            @Parameter(description = "Statut actif") @RequestParam(required = false) Boolean actif,
            @Parameter(description = "Numéro SIRET") @RequestParam(required = false) String siret,
            @Parameter(description = "Numéro FINESS") @RequestParam(required = false) String numeroFiness,
            @Parameter(description = "Numéro de page (0-based)") @RequestParam(defaultValue = "0") @Min(0) int page,
            @Parameter(description = "Taille de page") @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size,
            @Parameter(description = "Champ de tri") @RequestParam(defaultValue = "nomCommercial") String sortBy,
            @Parameter(description = "Direction du tri") @RequestParam(defaultValue = "asc") String sortDirection) {

        log.info("GET /api/v1/laboratoires - Recherche avec critères");

        LaboratoireSearchDTO searchDTO = LaboratoireSearchDTO.builder()
                .searchTerm(searchTerm)
                .typeLaboratoire(typeLaboratoire)
                .actif(actif)
                .siret(siret)
                .numeroFiness(numeroFiness)
                .build();

        PagedResponseDTO<LaboratoireResponseDTO> response = laboratoireService.searchLaboratoires(
                searchDTO, page, size, sortBy, sortDirection);

        return ResponseEntity.ok(response);
    }

    /**
     * Récupérer tous les laboratoires actifs
     */
    @GetMapping("/actifs")
    @Operation(
            summary = "Laboratoires actifs",
            description = "Récupère la liste de tous les laboratoires actifs (sans pagination)"
    )
    @ApiResponse(responseCode = "200", description = "Liste des laboratoires actifs")
    @PreAuthorize("hasRole('ADMIN') or hasRole('STAFF')")
    public ResponseEntity<List<LaboratoireResponseDTO>> getAllActiveLaboratoires() {
        log.info("GET /api/v1/laboratoires/actifs");

        List<LaboratoireResponseDTO> response = laboratoireService.getAllActiveLaboratoires();
        return ResponseEntity.ok(response);
    }

    /**
     * Récupérer les laboratoires par type
     */
    @GetMapping("/type/{type}")
    @Operation(
            summary = "Laboratoires par type",
            description = "Récupère tous les laboratoires actifs d'un type donné"
    )
    @ApiResponse(responseCode = "200", description = "Laboratoires du type spécifié")
    @PreAuthorize("hasRole('ADMIN') or hasRole('STAFF')")
    public ResponseEntity<List<LaboratoireResponseDTO>> getLaboratoiresByType(
            @Parameter(description = "Type de laboratoire") @PathVariable TypeLaboratoire type) {

        log.info("GET /api/v1/laboratoires/type/{}", type);

        List<LaboratoireResponseDTO> response = laboratoireService.getLaboratoiresByType(type);
        return ResponseEntity.ok(response);
    }

    // === Recherches spécifiques ===

    /**
     * Rechercher par SIRET
     */
    @GetMapping("/siret/{siret}")
    @Operation(
            summary = "Recherche par SIRET",
            description = "Trouve un laboratoire par son numéro SIRET"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Laboratoire trouvé"),
            @ApiResponse(responseCode = "404", description = "Aucun laboratoire avec ce SIRET")
    })
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<LaboratoireResponseDTO> findBySiret(
            @Parameter(description = "Numéro SIRET (14 chiffres)") @PathVariable String siret) {

        log.info("GET /api/v1/laboratoires/siret/{}", siret);

        LaboratoireResponseDTO response = laboratoireService.findBySiret(siret);
        return ResponseEntity.ok(response);
    }

    /**
     * Rechercher par numéro FINESS
     */
    @GetMapping("/finess/{numeroFiness}")
    @Operation(
            summary = "Recherche par FINESS",
            description = "Trouve un laboratoire par son numéro FINESS"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Laboratoire trouvé"),
            @ApiResponse(responseCode = "404", description = "Aucun laboratoire avec ce numéro FINESS")
    })
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<LaboratoireResponseDTO> findByNumeroFiness(
            @Parameter(description = "Numéro FINESS") @PathVariable String numeroFiness) {

        log.info("GET /api/v1/laboratoires/finess/{}", numeroFiness);

        LaboratoireResponseDTO response = laboratoireService.findByNumeroFiness(numeroFiness);
        return ResponseEntity.ok(response);
    }

    /**
     * Rechercher par code laboratoire
     */
    @GetMapping("/code/{codeLaboratoire}")
    @Operation(
            summary = "Recherche par code",
            description = "Trouve un laboratoire par son code interne"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Laboratoire trouvé"),
            @ApiResponse(responseCode = "404", description = "Aucun laboratoire avec ce code")
    })
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<LaboratoireResponseDTO> findByCodeLaboratoire(
            @Parameter(description = "Code interne du laboratoire") @PathVariable String codeLaboratoire) {

        log.info("GET /api/v1/laboratoires/code/{}", codeLaboratoire);

        LaboratoireResponseDTO response = laboratoireService.findByCodeLaboratoire(codeLaboratoire);
        return ResponseEntity.ok(response);
    }

    // === Actions spéciales ===

    /**
     * Activer/désactiver un laboratoire
     */
    @PatchMapping("/{id}/activation")
    @Operation(
            summary = "Activer/désactiver un laboratoire",
            description = "Modifie le statut actif d'un laboratoire sans affecter les autres données"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Statut modifié"),
            @ApiResponse(responseCode = "404", description = "Laboratoire non trouvé")
    })
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<LaboratoireResponseDTO> toggleActivation(
            @Parameter(description = "Identifiant unique du laboratoire") @PathVariable UUID id,
            @Parameter(description = "Nouveau statut actif") @RequestParam boolean actif) {

        log.info("PATCH /api/v1/laboratoires/{}/activation - Statut: {}", id, actif);

        LaboratoireResponseDTO response = laboratoireService.toggleActivation(id, actif);
        return ResponseEntity.ok(response);
    }

    // === Statistiques ===

    /**
     * Statistiques des laboratoires
     */
    @GetMapping("/statistiques")
    @Operation(
            summary = "Statistiques des laboratoires",
            description = "Récupère des statistiques globales sur les laboratoires du système"
    )
    @ApiResponse(responseCode = "200", description = "Statistiques générées")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getStatistiques() {
        log.info("GET /api/v1/laboratoires/statistiques");

        Map<String, Object> statistiques = laboratoireService.getStatistiques();
        return ResponseEntity.ok(statistiques);
    }
}