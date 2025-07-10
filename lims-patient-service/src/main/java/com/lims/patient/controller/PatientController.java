
package com.lims.patient.controller;

import com.lims.patient.dto.request.*;
import com.lims.patient.dto.response.*;
import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.PatientStatus;
import com.lims.patient.service.PatientService;
import com.lims.patient.service.PatientSearchService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Contrôleur REST pour la gestion des patients - Version centralisée corrigée
 */
@RestController
@RequestMapping("/api/v1/patients")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Patients", description = "API de gestion des patients")
public class PatientController {

    private final PatientService patientService;
    private final PatientSearchService patientSearchService;

    // ============================================
    // ENDPOINTS CRUD
    // ============================================

    /**
     * Créer un nouveau patient
     */
    @PostMapping
    @Operation(summary = "Créer un nouveau patient")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Patient créé avec succès"),
            @ApiResponse(responseCode = "400", description = "Données invalides"),
            @ApiResponse(responseCode = "409", description = "Patient déjà existant")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientResponse> createPatient(
            @Valid @RequestBody CreatePatientRequest request) {

        log.info("Création d'un nouveau patient: {} {}",
                request.personalInfo().prenom(), request.personalInfo().nom());

        PatientResponse response = patientService.createPatient(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Récupérer un patient par ID
     */
    @GetMapping("/{id}")
    @Operation(summary = "Récupérer un patient par ID")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Patient trouvé"),
            @ApiResponse(responseCode = "404", description = "Patient non trouvé")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN') or hasRole('PATIENT')")
    public ResponseEntity<PatientResponse> getPatient(
            @Parameter(description = "ID du patient") @PathVariable(value = "id") UUID id) {

        log.info("Récupération du patient: {}", id);

        PatientResponse response = patientService.getPatient(id);

        return ResponseEntity.ok(response);
    }

    /**
     * Mettre à jour un patient
     */
    @PutMapping("/{id}")
    @Operation(summary = "Mettre à jour un patient")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Patient mis à jour"),
            @ApiResponse(responseCode = "404", description = "Patient non trouvé"),
            @ApiResponse(responseCode = "400", description = "Données invalides")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientResponse> updatePatient(
            @Parameter(description = "ID du patient") @PathVariable(value = "id") UUID id,
            @Valid @RequestBody UpdatePatientRequest request) {

        log.info("Mise à jour du patient: {}", id);

        PatientResponse response = patientService.updatePatient(id, request);

        return ResponseEntity.ok(response);
    }

    /**
     * Supprimer un patient (soft delete)
     */
    @DeleteMapping("/{id}")
    @Operation(summary = "Supprimer un patient")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Patient supprimé"),
            @ApiResponse(responseCode = "404", description = "Patient non trouvé")
    })
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deletePatient(
            @Parameter(description = "ID du patient") @PathVariable(value = "id") UUID id) {

        log.info("Suppression du patient: {}", id);

        patientService.deletePatient(id);

        return ResponseEntity.noContent().build();
    }

    // ============================================
    // ENDPOINTS DE RECHERCHE
    // ============================================

    /**
     * Recherche multicritères de patients (POST recommandé)
     */
    @PostMapping("/search")
    @Operation(summary = "Recherche multicritères de patients")
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
     * Recherche simple par un seul critère (GET acceptable)
     */
    @GetMapping("/search/simple")
    @Operation(summary = "Recherche simple par un critère")
    @ApiResponse(responseCode = "200", description = "Résultats de recherche simple")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<PatientSummaryResponse>> simpleSearch(
            @Parameter(description = "Type de recherche")
            @RequestParam(value = "type") String type,

            @Parameter(description = "Valeur recherchée")
            @RequestParam(value = "value") String value,

            @Parameter(description = "Limite de résultats")
            @RequestParam(value = "limit", defaultValue = "20") int limit) {

        log.info("Recherche simple: {} = {}", type, value);

        List<PatientSummaryResponse> results = switch (type.toLowerCase()) {
            case "nom" -> patientSearchService.searchByNomPrenom(value, null);
            case "prenom" -> patientSearchService.searchByNomPrenom(null, value);
            // case "ville" -> patientSearchService.searchByVille(value);
            // case "medecin" -> patientSearchService.searchByMedecinTraitant(value);
            default -> throw new IllegalArgumentException("Type de recherche non supporté: " + type);
        };

        return ResponseEntity.ok(results.stream().limit(limit).toList());
    }

    /**
     * Recherche rapide (typeahead) - GET acceptable car simple
     */
    @GetMapping("/search/quick")
    @Operation(summary = "Recherche rapide de patients")
    @ApiResponse(responseCode = "200", description = "Résultats de recherche rapide")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<PatientSummaryResponse>> quickSearch(
            @Parameter(description = "Terme de recherche")
            @RequestParam(value = "query") String query,
            @Parameter(description = "Limite de résultats")
            @RequestParam(value = "limit", defaultValue = "10") int limit) {

        log.info("Recherche rapide: {}", query);

        List<PatientSummaryResponse> results = patientSearchService.quickSearch(query, limit);

        return ResponseEntity.ok(results);
    }

    // ============================================
    // ENDPOINTS DE RECHERCHE SPÉCIFIQUES
    // ============================================

    /**
     * Recherche par email
     */
    @GetMapping("/search/email")
    @Operation(summary = "Recherche par email")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientResponse> findByEmail(
            @Parameter(description = "Email du patient")
            @RequestParam(value = "email") String email) {

        log.info("Recherche par email: {}", email);

        Optional<PatientResponse> patient = patientService.findByEmail(email);

        return patient.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Recherche par téléphone
     */
    @GetMapping("/search/telephone")
    @Operation(summary = "Recherche par téléphone")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientResponse> findByTelephone(
            @Parameter(description = "Téléphone du patient")
            @RequestParam(value = "telephone") String telephone) {

        log.info("Recherche par téléphone: {}", telephone);

        Optional<PatientResponse> patient = patientService.findByTelephone(telephone);

        return patient.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Recherche par numéro de sécurité sociale
     */
    @GetMapping("/search/nir")
    @Operation(summary = "Recherche par numéro de sécurité sociale")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientResponse> findByNumeroSecu(
            @Parameter(description = "Numéro de sécurité sociale")
            @RequestParam(value = "numeroSecu") String numeroSecu) {

        log.info("Recherche par numéro de sécurité sociale");

        Optional<PatientResponse> patient = patientService.findByNumeroSecu(numeroSecu);

        return patient.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Recherche par ville
     */
    @GetMapping("/search/ville")
    @Operation(summary = "Recherche par ville")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<PatientSummaryResponse>> findByVille(
            @Parameter(description = "Ville")
            @RequestParam(value = "ville") String ville) {

        log.info("Recherche par ville: {}", ville);

        List<PatientSummaryResponse> patients = List.of(); // patientSearchService.searchByVille(ville);

        return ResponseEntity.ok(patients);
    }

    /**
     * Recherche par médecin traitant
     */
    @GetMapping("/search/medecin")
    @Operation(summary = "Recherche par médecin traitant")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<PatientSummaryResponse>> findByMedecinTraitant(
            @Parameter(description = "Médecin traitant")
            @RequestParam(value = "medecin") String medecin) {

        log.info("Recherche par médecin traitant: {}", medecin);

        List<PatientSummaryResponse> patients = List.of(); // patientSearchService.searchByMedecinTraitant(medecin);

        return ResponseEntity.ok(patients);
    }

    // ============================================
    // ENDPOINTS DE LISTE
    // ============================================

    /**
     * Liste des patients actifs
     */
    @GetMapping("/active")
    @Operation(summary = "Liste des patients actifs")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<PatientSummaryResponse>> getActivePatients(
            @Parameter(description = "Numéro de page")
            @RequestParam(value = "page", defaultValue = "0") int page,
            @Parameter(description = "Taille de la page")
            @RequestParam(value = "size", defaultValue = "20") int size) {

        log.info("Récupération des patients actifs");

        List<PatientSummaryResponse> patients = patientService.getActivePatients(page, size);

        return ResponseEntity.ok(patients);
    }

    /**
     * Liste des patients avec notifications
     */
    @GetMapping("/notifications")
    @Operation(summary = "Liste des patients avec notifications activées")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<PatientSummaryResponse>> getPatientsWithNotifications() {

        log.info("Récupération des patients avec notifications");

        List<PatientSummaryResponse> patients = List.of(); // patientSearchService.searchPatientsWithNotifications();

        return ResponseEntity.ok(patients);
    }

    /**
     * Statistiques des patients
     */
    @GetMapping("/stats")
    @Operation(summary = "Statistiques des patients")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientStatsResponse> getPatientStats() {

        log.info("Récupération des statistiques patients");

        PatientStatsResponse stats = PatientStatsResponse.builder()
                .totalPatientsActifs(patientSearchService.countActivePatients())
                .statistiquesParStatut(patientSearchService.getPatientStatisticsByStatus())
                .statistiquesParSexe(patientSearchService.getPatientStatisticsByGender())
                .statistiquesParVille(patientSearchService.getPatientStatisticsByCity())
                .build();

        return ResponseEntity.ok(stats);
    }
}