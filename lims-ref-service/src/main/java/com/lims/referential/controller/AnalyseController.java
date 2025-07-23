// AnalyseController.java
package com.lims.referential.controller;

import com.lims.referential.service.AnalyseService;
import com.lims.referential.enums.analyses.CategorieAnalyse;
import com.lims.referential.dto.response.PagedResponseDTO;
import com.lims.referential.dto.request.AnalyseRequestDTO;
import com.lims.referential.dto.response.AnalyseResponseDTO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Contrôleur REST pour la gestion des analyses biologiques
 */
@RestController
@RequestMapping("/api/v1/analyses")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Analyses Biologiques", description = "API de gestion des analyses biologiques avec codes NABM")
public class AnalyseController {

    private final AnalyseService analyseService;

    @Operation(summary = "Lister toutes les analyses", description = "Récupère la liste paginée de toutes les analyses biologiques actives")
    @ApiResponses({@ApiResponse(responseCode = "200", description = "Liste récupérée avec succès"), @ApiResponse(responseCode = "400", description = "Paramètres de pagination invalides")})
    @GetMapping
    public ResponseEntity<PagedResponseDTO<AnalyseResponseDTO>> getAllAnalyses(@Parameter(description = "Numéro de page (commence à 0)") @RequestParam(defaultValue = "0") int page, @Parameter(description = "Taille de la page (max 100)") @RequestParam(defaultValue = "20") int size, @Parameter(description = "Critère de tri (ex: libelle,asc)") @RequestParam(defaultValue = "libelle,asc") String sort) {

        log.debug("GET /api/v1/analyses - page: {}, size: {}, sort: {}", page, size, sort);

        // Validation des paramètres
        if (size > 100) size = 100;
        if (page < 0) page = 0;

        // Parse du critère de tri
        String[] sortParams = sort.split(",");
        String sortField = sortParams[0];
        Sort.Direction direction = sortParams.length > 1 && "desc".equalsIgnoreCase(sortParams[1]) ? Sort.Direction.DESC : Sort.Direction.ASC;

        Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortField));
        PagedResponseDTO<AnalyseResponseDTO> result = analyseService.findAll(pageable);

        return ResponseEntity.ok(result);
    }

    @Operation(summary = "Obtenir une analyse par ID", description = "Récupère les détails d'une analyse spécifique par son identifiant")
    @ApiResponses({@ApiResponse(responseCode = "200", description = "Analyse trouvée"), @ApiResponse(responseCode = "404", description = "Analyse non trouvée")})
    @GetMapping("/{id}")
    public ResponseEntity<AnalyseResponseDTO> getAnalyseById(@Parameter(description = "Identifiant unique de l'analyse") @PathVariable UUID id) {

        log.debug("GET /api/v1/analyses/{}", id);
        AnalyseResponseDTO analyse = analyseService.findById(id);
        return ResponseEntity.ok(analyse);
    }

    @Operation(summary = "Rechercher des analyses", description = "Recherche textuelle dans les analyses par libellé, code NABM ou description")
    @ApiResponses({@ApiResponse(responseCode = "200", description = "Recherche effectuée avec succès"), @ApiResponse(responseCode = "400", description = "Terme de recherche invalide")})
    @GetMapping("/search")
    public ResponseEntity<PagedResponseDTO<AnalyseResponseDTO>> searchAnalyses(@Parameter(description = "Terme de recherche") @RequestParam String q, @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size, @RequestParam(defaultValue = "libelle,asc") String sort) {

        log.debug("GET /api/v1/analyses/search - q: '{}', page: {}, size: {}", q, page, size);

        if (q == null || q.trim().length() < 2) {
            throw new IllegalArgumentException("Le terme de recherche doit contenir au moins 2 caractères");
        }

        // Parse du critère de tri
        String[] sortParams = sort.split(",");
        String sortField = sortParams[0];
        Sort.Direction direction = sortParams.length > 1 && "desc".equalsIgnoreCase(sortParams[1]) ? Sort.Direction.DESC : Sort.Direction.ASC;

        Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortField));
        PagedResponseDTO<AnalyseResponseDTO> result = analyseService.search(q.trim(), pageable);

        return ResponseEntity.ok(result);
    }

    @Operation(summary = "Auto-complétion des analyses", description = "Suggestions d'analyses pour l'auto-complétion")
    @GetMapping("/suggest")
    public ResponseEntity<List<AnalyseResponseDTO>> suggestAnalyses(@Parameter(description = "Préfixe pour l'auto-complétion") @RequestParam String q) {

        log.debug("GET /api/v1/analyses/suggest - q: '{}'", q);

        if (q == null || q.trim().length() < 1) {
            return ResponseEntity.ok(List.of());
        }

        List<AnalyseResponseDTO> suggestions = analyseService.suggest(q.trim());
        return ResponseEntity.ok(suggestions);
    }

    @Operation(summary = "Filtrer les analyses", description = "Filtrage multi-critères des analyses")
    @GetMapping("/filter")
    public ResponseEntity<PagedResponseDTO<AnalyseResponseDTO>> filterAnalyses(@Parameter(description = "Catégorie d'analyse") @RequestParam(required = false) CategorieAnalyse categorie, @Parameter(description = "Sous-catégorie d'analyse") @RequestParam(required = false) String sousCategorie, @Parameter(description = "Statut actif/inactif") @RequestParam(required = false) Boolean actif, @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size, @RequestParam(defaultValue = "libelle,asc") String sort) {

        log.debug("GET /api/v1/analyses/filter - catégorie: {}, sous-catégorie: {}, actif: {}", categorie, sousCategorie, actif);

        // Parse du critère de tri
        String[] sortParams = sort.split(",");
        String sortField = sortParams[0];
        Sort.Direction direction = sortParams.length > 1 && "desc".equalsIgnoreCase(sortParams[1]) ? Sort.Direction.DESC : Sort.Direction.ASC;

        Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortField));
        PagedResponseDTO<AnalyseResponseDTO> result = analyseService.findWithFilters(categorie, sousCategorie, actif, pageable);

        return ResponseEntity.ok(result);
    }

    @Operation(summary = "Créer une nouvelle analyse", description = "Crée une nouvelle analyse biologique avec validation des données")
    @ApiResponses({@ApiResponse(responseCode = "201", description = "Analyse créée avec succès"), @ApiResponse(responseCode = "400", description = "Données invalides"), @ApiResponse(responseCode = "409", description = "Code NABM déjà existant")})
    @PostMapping
    public ResponseEntity<AnalyseResponseDTO> createAnalyse(@Parameter(description = "Données de l'analyse à créer") @Valid @RequestBody AnalyseRequestDTO requestDTO) {

        log.info("POST /api/v1/analyses - Création d'une analyse avec code NABM: {}", requestDTO.getCodeNabm());

        AnalyseResponseDTO createdAnalyse = analyseService.create(requestDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdAnalyse);
    }

    @Operation(summary = "Mettre à jour une analyse", description = "Met à jour complètement une analyse existante")
    @ApiResponses({@ApiResponse(responseCode = "200", description = "Analyse mise à jour avec succès"), @ApiResponse(responseCode = "400", description = "Données invalides"), @ApiResponse(responseCode = "404", description = "Analyse non trouvée"), @ApiResponse(responseCode = "409", description = "Code NABM déjà existant")})
    @PutMapping("/{id}")
    public ResponseEntity<AnalyseResponseDTO> updateAnalyse(@Parameter(description = "Identifiant de l'analyse à modifier") @PathVariable UUID id, @Parameter(description = "Nouvelles données de l'analyse") @Valid @RequestBody AnalyseRequestDTO requestDTO) {

        log.info("PUT /api/v1/analyses/{} - Mise à jour de l'analyse", id);

        AnalyseResponseDTO updatedAnalyse = analyseService.update(id, requestDTO);
        return ResponseEntity.ok(updatedAnalyse);
    }

    @Operation(summary = "Mise à jour partielle d'une analyse", description = "Met à jour partiellement une analyse existante")
    @ApiResponses({@ApiResponse(responseCode = "200", description = "Analyse mise à jour avec succès"), @ApiResponse(responseCode = "400", description = "Données invalides"), @ApiResponse(responseCode = "404", description = "Analyse non trouvée")})
    @PatchMapping("/{id}")
    public ResponseEntity<AnalyseResponseDTO> patchAnalyse(@Parameter(description = "Identifiant de l'analyse à modifier") @PathVariable UUID id, @Parameter(description = "Données partielles de l'analyse") @RequestBody AnalyseRequestDTO requestDTO) {

        log.info("PATCH /api/v1/analyses/{} - Mise à jour partielle de l'analyse", id);

        AnalyseResponseDTO updatedAnalyse = analyseService.update(id, requestDTO);
        return ResponseEntity.ok(updatedAnalyse);
    }

    @Operation(summary = "Supprimer une analyse", description = "Supprime logiquement une analyse (soft delete)")
    @ApiResponses({@ApiResponse(responseCode = "204", description = "Analyse supprimée avec succès"), @ApiResponse(responseCode = "404", description = "Analyse non trouvée")})
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteAnalyse(@Parameter(description = "Identifiant de l'analyse à supprimer") @PathVariable UUID id) {

        log.info("DELETE /api/v1/analyses/{} - Suppression de l'analyse", id);

        analyseService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Statistiques des analyses", description = "Récupère les statistiques générales des analyses")
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getAnalysesStatistics() {
        log.debug("GET /api/v1/analyses/stats");

        Map<String, Object> statistics = analyseService.getStatistics();
        return ResponseEntity.ok(statistics);
    }

    @Operation(summary = "Export CSV des analyses", description = "Exporte toutes les analyses au format CSV")
    @GetMapping("/export")
    public ResponseEntity<String> exportAnalyses(@Parameter(description = "Format d'export (csv par défaut)") @RequestParam(defaultValue = "csv") String format) {

        log.info("GET /api/v1/analyses/export - format: {}", format);

        if (!"csv".equalsIgnoreCase(format)) {
            throw new IllegalArgumentException("Format non supporté: " + format);
        }

        // TODO: Implémenter l'export CSV
        return ResponseEntity.ok("Export CSV non encore implémenté");
    }

    @Operation(summary = "Import CSV des analyses", description = "Importe des analyses depuis un fichier CSV")
    @PostMapping("/import")
    public ResponseEntity<Map<String, Object>> importAnalyses(@Parameter(description = "Remplacer les analyses existantes") @RequestParam(defaultValue = "false") boolean replaceExisting) {

        log.info("POST /api/v1/analyses/import - replaceExisting: {}", replaceExisting);

        // TODO: Implémenter l'import CSV
        Map<String, Object> result = Map.of("message", "Import CSV non encore implémenté", "imported", 0, "errors", List.of());

        return ResponseEntity.ok(result);
    }
}