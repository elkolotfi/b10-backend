package com.lims.patient.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.lims.patient.dto.error.ErrorResponse;
import com.lims.patient.dto.request.CreatePatientRequest;
import com.lims.patient.dto.request.PatientSearchRequest;
import com.lims.patient.dto.request.UpdatePatientRequest;
import com.lims.patient.dto.response.PatientResponse;
import com.lims.patient.dto.response.PatientSearchResponse;
import com.lims.patient.dto.response.PatientSummaryResponse;
import com.lims.patient.service.PatientAuditService;
import com.lims.patient.service.PatientSearchService;
import com.lims.patient.service.PatientService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/patients")
@RequiredArgsConstructor
@Slf4j
@Validated
@Tag(name = "Patients", description = "Gestion des patients")
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class PatientController {
    private final PatientAuditService auditService;
    private final PatientService patientService;
    private final PatientSearchService patientSearchService;

    /**
     * Crée un nouveau patient avec toutes ses informations
     */
    @PostMapping
    @Operation(summary = "Créer un nouveau patient",
            description = "Crée un patient complet avec données personnelles, contact, assurances, spécificités et commentaire")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Patient créé avec succès",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = PatientResponse.class))),
            @ApiResponse(responseCode = "400", description = "Données invalides",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "409", description = "Patient déjà existant (NIR/email/téléphone)",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientResponse> createPatient(
            @Valid @RequestBody CreatePatientRequest request,
            Authentication authentication) {

        log.info("Création d'un nouveau patient: {} {} par {}",
                request.personalInfo().prenom(),
                request.personalInfo().nom(),
                authentication.getName());

        // Passer directement la requête + créateur séparément
        PatientResponse response = patientService.createPatient(request, authentication.getName());

        // Audit simple
        /*auditService.logPatientCreation(
                response,
                authentication.getName()
        );*/

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // Méthode à ajouter dans la classe PatientController
    @PatchMapping("/{id}")
    @Operation(summary = "Mettre à jour partiellement un patient",
            description = "Met à jour les données d'un patient avec JSON Patch (RFC 6902)")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Patient mis à jour avec succès",
                    content = @Content(schema = @Schema(implementation = PatientResponse.class))),
            @ApiResponse(responseCode = "404", description = "Patient non trouvé",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "400", description = "Opérations patch invalides",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientResponse> updatePatient(
            @Parameter(description = "ID du patient à mettre à jour")
            @PathVariable(name = "id") UUID id,
            @RequestBody JsonNode patchNode,
            Authentication authentication) {

        String updatedBy = authentication.getName();
        PatientResponse updatedPatient = patientService.updatePatient(id, patchNode, updatedBy);

        return ResponseEntity.ok(updatedPatient);
    }

    /**
     * Recherche multicritères de patients (POST recommandé)
     */
    @PostMapping("/search")
    @Operation(summary = "Recherche multicritères de patients",
            description = "Recherche avancée avec support du lastName complet ou lastName/prénom séparés")
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
     * Recherche rapide par lastName complet (GET)
     */
    @GetMapping("/search/quick")
    @Operation(summary = "Recherche rapide par lastName complet",
            description = "Recherche rapide limitée à 10 résultats pour autocomplétion")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Résultats de recherche rapide"),
            @ApiResponse(responseCode = "400", description = "Paramètre de recherche invalide")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<PatientSummaryResponse>> quickSearch(
            @Parameter(description = "Nom complet à rechercher (lastName et/ou prénom)")
            @RequestParam @Size(min = 2, max = 100, message = "Le lastName complet doit contenir entre 2 et 100 caractères")
            String nomComplet) {

        log.info("Recherche rapide par lastName complet: {}", nomComplet);

        List<PatientSummaryResponse> results = patientService.quickSearchByNomComplet(nomComplet);

        return ResponseEntity.ok(results);
    }

    /**
     * Recherche par lastName complet avec pagination (GET)
     */
    @GetMapping("/search/lastName-complet")
    @Operation(summary = "Recherche par lastName complet avec pagination",
            description = "Recherche par lastName complet avec support de la pagination")
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

        log.info("Recherche par lastName complet avec pagination: {} (page: {}, size: {})",
                nomComplet, page, size);

        PatientSearchResponse response = patientSearchService.searchByNomComplet(nomComplet, page, size);

        return ResponseEntity.ok(response);
    }

    /**
     * Autocomplétion pour le lastName complet
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
            @Parameter(description = "Début du lastName à rechercher (minimum 2 caractères)")
            @RequestParam @Size(min = 2, max = 50) String input) {

        log.info("Suggestion d'autocomplétion pour: {}", input);

        List<String> suggestions = patientService.suggestNomComplet(input);

        return ResponseEntity.ok(suggestions);
    }

    /**
     * Recherche par lastName et prénom séparés (rétrocompatibilité)
     */
    @GetMapping("/search/lastName-firstName")
    @Operation(summary = "Recherche par lastName et prénom séparés",
            description = "Méthode legacy pour la recherche par lastName et prénom séparés")
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

        log.info("Recherche legacy par lastName: {} et prénom: {}", nom, prenom);

        List<PatientSummaryResponse> results = patientService.searchByNomPrenom(nom, prenom);

        return ResponseEntity.ok(results);
    }

    /**
     * Recherche par lastName et prénom séparés (rétrocompatibilité)
     */
    @GetMapping("/search/telephone")
    @Operation(summary = "Recherche par telephone",
            description = "Méthode legacy pour la recherche par numéro de telephone")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Liste des patients trouvés"),
            @ApiResponse(responseCode = "400", description = "Paramètres invalides")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    @Deprecated(since = "2.0", forRemoval = false)
    public ResponseEntity<List<PatientSummaryResponse>> searchByPhone(
            @Parameter(description = "telephone")
            @RequestParam(value = "telephone") @Size(max = 100) String phone) {

        log.info("Recherche legacy par telephone: {}", phone);

        List<PatientSummaryResponse> results = patientService.searchByPhone(phone);

        return ResponseEntity.ok(results);
    }

    // ============================================
    // GET PATIENT BY ID
    // ============================================

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN_LAB', 'SECRETAIRE', 'PRELEVEUR', 'TECHNICIEN', 'SUPER_ADMIN') or " +
            "(hasRole('PATIENT') and @patientService.isPatientOwner(authentication.name, #id))")
    @Operation(
            summary = "Récupérer les détails d'un patient",
            description = "Récupère toutes les informations d'un patient spécifique. " +
                    "Accessible au personnel du laboratoire ou au patient lui-même."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Patient trouvé",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = PatientResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Patient non trouvé",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Accès interdit - Patient ne peut accéder qu'à ses propres données"
            )
    })
    public ResponseEntity<PatientResponse> getPatientById(
            @Parameter(description = "ID du patient", required = true)
            @PathVariable(value = "id") UUID id,
            Authentication authentication) {

        log.info("Consultation du patient {} par l'utilisateur: {}", id, authentication.getName());

        // Détermination du type d'utilisateur
        String userType = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().contains("PATIENT")) ? "PATIENT" : "STAFF";

        // Audit de l'accès
        /*auditService.logPatientAccess(
                id,
                "VIEW_PATIENT",
                "Consultation des détails du patient",
                authentication.getName(),
                userType
        );*/

        PatientResponse patient = patientService.getPatient(id);

        log.info("Patient {} consulté avec succès", id);

        return ResponseEntity.ok(patient);
    }
}