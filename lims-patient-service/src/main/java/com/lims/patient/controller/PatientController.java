package com.lims.patient.controller;

import com.lims.patient.dto.SearchStats;
import com.lims.patient.dto.error.ErrorResponse;
import com.lims.patient.dto.request.CreatePatientRequest;
import com.lims.patient.dto.request.PatientSearchRequest;
import com.lims.patient.dto.request.UpdatePatientRequest;
import com.lims.patient.dto.response.PatientResponse;
import com.lims.patient.dto.response.PatientSearchResponse;
import com.lims.patient.dto.response.PatientSummaryResponse;
import com.lims.patient.enums.PatientStatus;
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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Contrôleur REST pour la gestion des patients
 * -
 * Sécurité :
 * - Staff (realm lims-staff) : CRUD complet
 * - Patient (realm lims-patient) : Lecture seule de ses propres données
 * -
 * Endpoints disponibles :
 * - POST /api/v1/patients - Créer patient (Staff uniquement)
 * - GET /api/v1/patients - Liste paginée + recherche (Staff uniquement)
 * - GET /api/v1/patients/{id} - Détail patient (Staff + Patient propriétaire)
 * - PUT /api/v1/patients/{id} - Modifier patient (Staff uniquement)
 * - DELETE /api/v1/patients/{id} - Soft delete patient (Staff uniquement)
 */
@RestController
@RequestMapping("/api/v1/patients")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "👤 Patients", description = "API de gestion des patients")
public class PatientController {

    private final PatientService patientService;
    private final PatientSearchService patientSearchService;
    private final PatientAuditService auditService;

    // ============================================
    // CREATE PATIENT
    // ============================================

    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN_LAB', 'SECRETAIRE')")
    @Operation(
            summary = "Créer un nouveau patient",
            description = "Crée un nouveau patient avec toutes ses informations (personnelles, contacts, assurances). " +
                    "Accessible uniquement aux administrateurs de laboratoire et secrétaires."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "Patient créé avec succès",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = PatientResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Données invalides",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Patient déjà existant (NIR en doublon)",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Accès interdit - Rôle insuffisant"
            )
    })
    public ResponseEntity<PatientResponse> createPatient(
            @Valid @RequestBody CreatePatientRequest request,
            Authentication authentication) {

        log.info("Création d'un nouveau patient par l'utilisateur: {}", authentication.getName());

        // Audit de la tentative de création
        auditService.logPatientAccess(
                null,
                "CREATE_PATIENT_ATTEMPT",
                "Tentative de création d'un patient",
                authentication.getName(),
                "STAFF"
        );

        try {
            // Ajout de l'utilisateur créateur dans la requête
            CreatePatientRequest requestWithCreator = CreatePatientRequest.builder()
                    .personalInfo(request.personalInfo())
                    .contactInfo(request.contactInfo())
                    .insurances(request.insurances())
                    .consent(request.consent())
                    .createdBy(authentication.getName())
                    .build();

            PatientResponse patient = patientService.createPatient(requestWithCreator);

            log.info("Patient créé avec succès - ID: {}", patient.id());

            // Audit de la création réussie
            auditService.logPatientAccess(
                    UUID.fromString(patient.id()),
                    "CREATE_PATIENT_SUCCESS",
                    "Patient créé avec succès",
                    authentication.getName(),
                    "STAFF"
            );

            return ResponseEntity.status(HttpStatus.CREATED).body(patient);

        } catch (Exception e) {
            log.error("Erreur lors de la création du patient", e);

            // Audit de l'échec
            auditService.logPatientAccess(
                    null,
                    "CREATE_PATIENT_FAILURE",
                    "Échec de la création du patient: " + e.getMessage(),
                    authentication.getName(),
                    "STAFF"
            );

            throw e;
        }
    }

    // ============================================
    // GET PATIENTS WITH SEARCH
    // ============================================

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN_LAB', 'SECRETAIRE', 'PRELEVEUR', 'TECHNICIEN')")
    @Operation(
            summary = "Recherche de patients",
            description = "Recherche de patients selon les critères de l'interface frontend. " +
                    "Au moins un critère principal est obligatoire : NIR, nom complet, date de naissance, téléphone ou email. " +
                    "Accessible à tout le personnel du laboratoire."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Résultats de recherche récupérés avec succès",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = PatientSearchResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Critères de recherche invalides - Au moins un critère principal requis",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Accès interdit - Rôle insuffisant"
            )
    })
    public ResponseEntity<PatientSearchResponse> searchPatients(
            @Valid @RequestBody PatientSearchRequest searchRequest,
            Authentication authentication) {

        log.info("Recherche de patients par l'utilisateur: {} avec critères: NIR={}, nomComplet={}, dateNaissance={}, telephone={}, email={}",
                authentication.getName(),
                searchRequest.numeroSecuSociale(),
                searchRequest.nomComplet(),
                searchRequest.dateNaissance(),
                searchRequest.telephone(),
                searchRequest.email());

        // Validation qu'au moins un critère principal est fourni
        if (!searchRequest.hasValidSearchCriteria()) {
            log.warn("Tentative de recherche sans critère principal par l'utilisateur: {}", authentication.getName());

            ErrorResponse error = ErrorResponse.builder()
                    .code("INVALID_SEARCH_CRITERIA")  // ✅ Correspond au champ 'code'
                    .message("Au moins un critère de recherche principal est requis : NIR, nom complet, date de naissance, téléphone ou email")
                    .detail("Les critères de recherche acceptés sont : numeroSecuSociale, nomComplet, dateNaissance, telephone, email")  // ✅ Détail supplémentaire
                    .path("/api/v1/patients")
                    .timestamp(LocalDateTime.now())
                    .fieldErrors(null)  // ✅ Pas d'erreurs de champs spécifiques
                    .build();

            // Audit de l'échec de validation
            auditService.logPatientAccess(
                    null,
                    "SEARCH_PATIENTS_VALIDATION_ERROR",
                    "Recherche refusée : critères insuffisants",
                    authentication.getName(),
                    "STAFF"
            );

            return ResponseEntity.badRequest().build(); // Retourner une erreur HTTP 400 standard
        }

        // Audit de la recherche
        auditService.logPatientAccess(
                null,
                "SEARCH_PATIENTS",
                String.format("Recherche de patients avec critères: NIR=%s, nomComplet=%s, dateNaissance=%s, telephone=%s, email=%s",
                        searchRequest.numeroSecuSociale(),
                        searchRequest.nomComplet(),
                        searchRequest.dateNaissance(),
                        searchRequest.telephone(),
                        searchRequest.email()),
                authentication.getName(),
                "STAFF"
        );

        try {
            PatientSearchResponse response = patientSearchService.searchPatients(searchRequest);

            log.info("Recherche terminée - {} patients trouvés sur {} total",
                    response.patients().size(), response.pageInfo().totalElements());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Erreur lors de la recherche de patients", e);

            // Audit de l'échec
            auditService.logPatientAccess(
                    null,
                    "SEARCH_PATIENTS_FAILURE",
                    "Échec de la recherche de patients: " + e.getMessage(),
                    authentication.getName(),
                    "STAFF"
            );

            throw e;
        }
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
            @PathVariable UUID id,
            Authentication authentication) {

        log.info("Consultation du patient {} par l'utilisateur: {}", id, authentication.getName());

        // Détermination du type d'utilisateur
        String userType = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().contains("PATIENT")) ? "PATIENT" : "STAFF";

        // Audit de l'accès
        auditService.logPatientAccess(
                id,
                "VIEW_PATIENT",
                "Consultation des détails du patient",
                authentication.getName(),
                userType
        );

        PatientResponse patient = patientService.getPatientById(id);

        log.info("Patient {} consulté avec succès", id);

        return ResponseEntity.ok(patient);
    }

    // ============================================
    // UPDATE PATIENT
    // ============================================

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN_LAB', 'SECRETAIRE')")
    @Operation(
            summary = "Modifier un patient",
            description = "Met à jour les informations d'un patient existant. " +
                    "Seuls les champs fournis sont modifiés (mise à jour partielle). " +
                    "Accessible uniquement aux administrateurs de laboratoire et secrétaires."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Patient modifié avec succès",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = PatientResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Données invalides",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)
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
                    description = "Accès interdit - Rôle insuffisant"
            )
    })
    public ResponseEntity<PatientResponse> updatePatient(
            @Parameter(description = "ID du patient à modifier", required = true)
            @PathVariable UUID id,
            @Valid @RequestBody UpdatePatientRequest request,
            Authentication authentication) {

        log.info("Modification du patient {} par l'utilisateur: {}", id, authentication.getName());

        // Audit de la tentative de modification
        auditService.logPatientAccess(
                id,
                "UPDATE_PATIENT_ATTEMPT",
                "Tentative de modification du patient",
                authentication.getName(),
                "STAFF"
        );

        try {
            // Ajout de l'utilisateur modificateur dans la requête
            UpdatePatientRequest requestWithModifier = UpdatePatientRequest.builder()
                    .personalInfo(request.personalInfo())
                    .contactInfo(request.contactInfo())
                    .consent(request.consent())
                    .modifiedBy(authentication.getName())
                    .build();

            PatientResponse patient = patientService.updatePatient(id, requestWithModifier);

            log.info("Patient {} modifié avec succès", id);

            // Audit de la modification réussie
            auditService.logPatientAccess(
                    id,
                    "UPDATE_PATIENT_SUCCESS",
                    "Patient modifié avec succès",
                    authentication.getName(),
                    "STAFF"
            );

            return ResponseEntity.ok(patient);

        } catch (Exception e) {
            log.error("Erreur lors de la modification du patient {}", id, e);

            // Audit de l'échec
            auditService.logPatientAccess(
                    id,
                    "UPDATE_PATIENT_FAILURE",
                    "Échec de la modification du patient: " + e.getMessage(),
                    authentication.getName(),
                    "STAFF"
            );

            throw e;
        }
    }

    // ============================================
    // DELETE PATIENT (SOFT DELETE)
    // ============================================

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN_LAB')")
    @Operation(
            summary = "Supprimer un patient (soft delete)",
            description = "Effectue une suppression logique du patient (soft delete). " +
                    "Le patient reste en base mais devient inaccessible. " +
                    "Accessible uniquement aux administrateurs de laboratoire."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "204",
                    description = "Patient supprimé avec succès"
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
                    description = "Accès interdit - Seuls les administrateurs peuvent supprimer"
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Suppression impossible - Patient a des données liées actives",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)
                    )
            )
    })
    public ResponseEntity<Void> deletePatient(
            @Parameter(description = "ID du patient à supprimer", required = true)
            @PathVariable UUID id,
            Authentication authentication) {

        log.warn("SUPPRESSION du patient {} demandée par l'utilisateur: {}", id, authentication.getName());

        // Audit de la tentative de suppression
        auditService.logPatientAccess(
                id,
                "DELETE_PATIENT_ATTEMPT",
                "Tentative de suppression du patient",
                authentication.getName(),
                "STAFF"
        );

        try {
            patientService.deletePatient(id, authentication.getName());

            log.warn("Patient {} supprimé avec succès par {}", id, authentication.getName());

            // Audit de la suppression réussie
            auditService.logPatientAccess(
                    id,
                    "DELETE_PATIENT_SUCCESS",
                    "Patient supprimé avec succès (soft delete)",
                    authentication.getName(),
                    "STAFF"
            );

            return ResponseEntity.noContent().build();

        } catch (Exception e) {
            log.error("Erreur lors de la suppression du patient {}", id, e);

            // Audit de l'échec
            auditService.logPatientAccess(
                    id,
                    "DELETE_PATIENT_FAILURE",
                    "Échec de la suppression du patient: " + e.getMessage(),
                    authentication.getName(),
                    "STAFF"
            );

            throw e;
        }
    }

    // ============================================
    // SEARCH ENDPOINTS
    // ============================================

    @GetMapping("/search/by-nir/{nir}")
    @PreAuthorize("hasAnyRole('ADMIN_LAB', 'SECRETAIRE', 'PRELEVEUR')")
    @Operation(
            summary = "Rechercher un patient par NIR",
            description = "Recherche un patient par son numéro de sécurité sociale. " +
                    "Accessible au personnel autorisé du laboratoire."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Patient trouvé",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = PatientSummaryResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Patient non trouvé"
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Accès interdit - Rôle insuffisant"
            )
    })
    public ResponseEntity<PatientSummaryResponse> getPatientByNir(
            @Parameter(description = "Numéro de sécurité sociale complet (15 chiffres)", required = true)
            @PathVariable String nir,
            Authentication authentication) {

        log.info("Recherche patient par NIR par l'utilisateur: {}", authentication.getName());

        // Audit de la recherche par NIR (sensible)
        auditService.logPatientAccess(
                null,
                "SEARCH_BY_NIR",
                "Recherche patient par numéro de sécurité sociale",
                authentication.getName(),
                "STAFF"
        );

        PatientSummaryResponse patient = patientSearchService.findPatientByNir(nir);

        if (patient != null) {
            log.info("Patient trouvé par NIR - ID: {}", patient.id());
        } else {
            log.info("Aucun patient trouvé pour ce NIR");
        }

        return patient != null ? ResponseEntity.ok(patient) : ResponseEntity.notFound().build();
    }

    @GetMapping("/search/by-phone/{phone}")
    @PreAuthorize("hasAnyRole('ADMIN_LAB', 'SECRETAIRE', 'PRELEVEUR')")
    @Operation(
            summary = "Rechercher un patient par téléphone",
            description = "Recherche un patient par son numéro de téléphone. " +
                    "Accessible au personnel autorisé du laboratoire."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Patient trouvé",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = PatientSummaryResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Patient non trouvé"
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Accès interdit - Rôle insuffisant"
            )
    })
    public ResponseEntity<PatientSummaryResponse> getPatientByPhone(
            @Parameter(description = "Numéro de téléphone", required = true)
            @PathVariable String phone,
            Authentication authentication) {

        log.info("Recherche patient par téléphone par l'utilisateur: {}", authentication.getName());

        // Audit de la recherche par téléphone
        auditService.logPatientAccess(
                null,
                "SEARCH_BY_PHONE",
                "Recherche patient par numéro de téléphone",
                authentication.getName(),
                "STAFF"
        );

        PatientSummaryResponse patient = patientSearchService.findPatientByPhone(phone);

        if (patient != null) {
            log.info("Patient trouvé par téléphone - ID: {}", patient.id());
        } else {
            log.info("Aucun patient trouvé pour ce téléphone");
        }

        return patient != null ? ResponseEntity.ok(patient) : ResponseEntity.notFound().build();
    }

    // ============================================
    // STATISTICS ENDPOINT
    // ============================================

    @GetMapping("/stats")
    @PreAuthorize("hasAnyRole('ADMIN_LAB', 'RESPONSABLE_QUALITE')")
    @Operation(
            summary = "Statistiques des patients",
            description = "Récupère les statistiques générales des patients du laboratoire. " +
                    "Accessible aux administrateurs et responsables qualité."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Statistiques récupérées avec succès",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = SearchStats.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Accès interdit - Rôle insuffisant"
            )
    })
    public ResponseEntity<SearchStats> getPatientStats(Authentication authentication) {

        log.info("Consultation des statistiques patients par l'utilisateur: {}", authentication.getName());

        // Audit de la consultation des statistiques
        auditService.logPatientAccess(
                null,
                "VIEW_PATIENT_STATS",
                "Consultation des statistiques patients",
                authentication.getName(),
                "STAFF"
        );

        SearchStats stats = patientSearchService.getPatientStatistics();

        return ResponseEntity.ok(stats);
    }
}