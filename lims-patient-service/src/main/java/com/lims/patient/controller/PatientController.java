package com.lims.patient.controller;

import com.lims.patient.dto.request.PatientSearchRequest;
import com.lims.patient.dto.response.PatientSearchResponse;
import com.lims.patient.dto.response.PatientSummaryResponse;
import com.lims.patient.service.PatientSearchService;
import com.lims.patient.service.PatientService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/patients")
@RequiredArgsConstructor
@Slf4j
@Validated
@Tag(name = "Patients", description = "Gestion des patients")
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class PatientController {

    private final PatientService patientService;
    private final PatientSearchService patientSearchService;

    /**
     * Recherche multicritères de patients (POST recommandé)
     */
    @PostMapping("/search")
    @Operation(summary = "Recherche multicritères de patients",
            description = "Recherche avancée avec support du nom complet ou nom/prénom séparés")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Résultats de recherche"),
            @ApiResponse(responseCode = "400", description = "Critères de recherche invalides")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientSearchResponse> searchPatients(
            @Valid @RequestBody PatientSearchRequest request) {

        log.info("Recherche de patients avec critères: {}", request);

        PatientSearchResponse response = patientService.searchPatients(request);

        return ResponseEntity.ok(response);
    }

    /**
     * Recherche rapide par nom complet (GET)
     */
    @GetMapping("/search/quick")
    @Operation(summary = "Recherche rapide par nom complet",
            description = "Recherche rapide limitée à 10 résultats pour autocomplétion")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Résultats de recherche rapide"),
            @ApiResponse(responseCode = "400", description = "Paramètre de recherche invalide")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<PatientSummaryResponse>> quickSearch(
            @Parameter(description = "Nom complet à rechercher (nom et/ou prénom)")
            @RequestParam @Size(min = 2, max = 100, message = "Le nom complet doit contenir entre 2 et 100 caractères")
            String nomComplet) {

        log.info("Recherche rapide par nom complet: {}", nomComplet);

        List<PatientSummaryResponse> results = patientService.quickSearchByNomComplet(nomComplet);

        return ResponseEntity.ok(results);
    }

    /**
     * Recherche par nom complet avec pagination (GET)
     */
    @GetMapping("/search/nom-complet")
    @Operation(summary = "Recherche par nom complet avec pagination",
            description = "Recherche par nom complet avec support de la pagination")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Résultats de recherche paginés"),
            @ApiResponse(responseCode = "400", description = "Paramètres invalides")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientSearchResponse> searchByNomComplet(
            @Parameter(description = "Nom complet à rechercher")
            @RequestParam @Size(min = 2, max = 100) String nomComplet,

            @Parameter(description = "Numéro de page (0-based)")
            @RequestParam(defaultValue = "0") @Min(0) int page,

            @Parameter(description = "Taille de page")
            @RequestParam(defaultValue = "10") @Min(1) @Max(100) int size) {

        log.info("Recherche par nom complet avec pagination: {} (page: {}, size: {})",
                nomComplet, page, size);

        PatientSearchResponse response = patientSearchService.searchByNomComplet(nomComplet, page, size);

        return ResponseEntity.ok(response);
    }

    /**
     * Autocomplétion pour le nom complet
     */
    @GetMapping("/search/suggest")
    @Operation(summary = "Suggestions pour autocomplétion",
            description = "Retourne des suggestions de noms complets pour l'autocomplétion")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Liste des suggestions"),
            @ApiResponse(responseCode = "400", description = "Paramètre invalide")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<String>> suggestNomComplet(
            @Parameter(description = "Début du nom à rechercher (minimum 2 caractères)")
            @RequestParam @Size(min = 2, max = 50) String input) {

        log.info("Suggestion d'autocomplétion pour: {}", input);

        List<String> suggestions = patientService.suggestNomComplet(input);

        return ResponseEntity.ok(suggestions);
    }

    /**
     * Recherche par nom et prénom séparés (rétrocompatibilité)
     */
    @GetMapping("/search/nom-prenom")
    @Operation(summary = "Recherche par nom et prénom séparés",
            description = "Méthode legacy pour la recherche par nom et prénom séparés")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Liste des patients trouvés"),
            @ApiResponse(responseCode = "400", description = "Paramètres invalides")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    @Deprecated(since = "2.0", forRemoval = false)
    public ResponseEntity<List<PatientSummaryResponse>> searchByNomPrenom(
            @Parameter(description = "Nom du patient")
            @RequestParam(required = false) @Size(max = 100) String nom,

            @Parameter(description = "Prénom du patient")
            @RequestParam(required = false) @Size(max = 100) String prenom) {

        log.info("Recherche legacy par nom: {} et prénom: {}", nom, prenom);

        List<PatientSummaryResponse> results = patientService.searchByNomPrenom(nom, prenom);

        return ResponseEntity.ok(results);
    }
}