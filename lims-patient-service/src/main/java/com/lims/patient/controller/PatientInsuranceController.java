package com.lims.patient.controller;

import com.lims.patient.dto.request.InsuranceRequest;
import com.lims.patient.dto.response.PatientInsuranceResponse;
import com.lims.patient.service.PatientInsuranceService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Contrôleur REST pour la gestion des assurances/mutuelles des patients.
 * Utilisé par le composant InsuranceManagement du frontend.
 */
@RestController
@RequestMapping("/api/v1/patients") // PAS de {patientId} ici
@Tag(name = "Patient Insurances", description = "API de gestion des assurances/mutuelles des patients")
@SecurityRequirement(name = "Bearer Authentication")
@RequiredArgsConstructor
@Slf4j
public class PatientInsuranceController {

    private final PatientInsuranceService insuranceService;


    @GetMapping("/{patientId}/insurances") // Path variable ICI
    @Operation(summary = "Lister les assurances du patient")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<List<PatientInsuranceResponse>> getPatientInsurances(
            @PathVariable(name = "patientId") UUID patientId,
            @RequestParam(name= "show-all", defaultValue = "false") boolean includeInactive) {

        log.debug("Récupération des assurances pour le patient {} (includeInactive: {})", patientId, includeInactive);

        List<PatientInsuranceResponse> insurances = insuranceService.getPatientInsurances(
                patientId, includeInactive);

        return ResponseEntity.ok(insurances);
    }

    @PostMapping("/{patientId}/insurances") // Path variable ICI
    @Operation(summary = "Ajouter une assurance/mutuelle")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SECRETAIRE')")
    public ResponseEntity<PatientInsuranceResponse> addInsurance(
            @PathVariable(name = "patientId") UUID patientId,
            @Valid @RequestBody InsuranceRequest request,
            Authentication authentication) {

        log.info("Ajout d'une assurance pour le patient {} par {}", patientId, authentication.getName());

        PatientInsuranceResponse response = insuranceService.addInsurance(
                patientId, request, authentication.getName());

        log.info("Assurance {} créée avec succès pour le patient {}", response.id(), patientId);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/{patientId}/insurances/{insuranceId}") // Path variables ICI
    @Operation(summary = "Détails d'une assurance")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<PatientInsuranceResponse> getInsuranceDetails(
            @PathVariable(name = "patientId") UUID patientId,
            @PathVariable(name = "insuranceId") UUID insuranceId) {

        log.debug("Récupération des détails de l'assurance {} pour le patient {}", insuranceId, patientId);

        PatientInsuranceResponse insurance = insuranceService.getInsuranceById(patientId, insuranceId);
        return ResponseEntity.ok(insurance);
    }

    @PutMapping("/{patientId}/insurances/{insuranceId}") // Path variables ICI
    @Operation(summary = "Modifier une assurance")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SECRETAIRE')")
    public ResponseEntity<PatientInsuranceResponse> updateInsurance(
            @PathVariable(name = "patientId") UUID patientId,
            @PathVariable(name = "insuranceId") UUID insuranceId,
            @Valid @RequestBody InsuranceRequest request,
            Authentication authentication) {

        log.info("Modification de l'assurance {} pour le patient {} par {}",
                insuranceId, patientId, authentication.getName());

        PatientInsuranceResponse response = insuranceService.updateInsurance(
                patientId, insuranceId, request, authentication.getName());

        log.info("Assurance {} mise à jour avec succès", insuranceId);
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/{patientId}/insurances/{insuranceId}/status") // Path variables ICI
    @Operation(summary = "Modifier le statut d'une assurance")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SECRETAIRE')")
    public ResponseEntity<PatientInsuranceResponse> updateInsuranceStatus(
            @PathVariable(name = "patientId") UUID patientId,
            @PathVariable(name = "insuranceId") UUID insuranceId,
            @RequestParam boolean active,
            Authentication authentication) {

        log.info("Modification du statut de l'assurance {} à {} par {}",
                insuranceId, active, authentication.getName());

        PatientInsuranceResponse response = insuranceService.updateInsuranceStatus(
                patientId, insuranceId, active, authentication.getName());

        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{patientId}/insurances/{insuranceId}") // Path variables ICI
    @Operation(summary = "Supprimer une assurance")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteInsurance(
            @PathVariable UUID patientId,
            @PathVariable UUID insuranceId,
            @RequestParam String reason,
            Authentication authentication) {

        log.warn("Suppression de l'assurance {} pour le patient {} par {} - Motif: {}",
                insuranceId, patientId, authentication.getName(), reason);

        insuranceService.deleteInsurance(patientId, insuranceId, reason, authentication.getName());

        log.info("Assurance {} supprimée définitivement", insuranceId);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{patientId}/insurances/active") // Path variable ICI
    @Operation(summary = "Assurances actives du patient")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<List<PatientInsuranceResponse>> getActiveInsurances(
            @PathVariable UUID patientId) {

        log.debug("Récupération des assurances actives pour le patient {}", patientId);

        List<PatientInsuranceResponse> activeInsurances = insuranceService.getActiveInsurances(patientId);
        return ResponseEntity.ok(activeInsurances);
    }

    @PostMapping("/{patientId}/insurances/{insuranceId}/validate-document") // Path variables ICI
    @Operation(summary = "Valider le document d'assurance")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SECRETAIRE')")
    public ResponseEntity<PatientInsuranceResponse> validateInsuranceDocument(
            @PathVariable UUID patientId,
            @PathVariable UUID insuranceId,
            @RequestParam(required = false) String validationComment,
            Authentication authentication) {

        log.info("Validation du document de l'assurance {} par {}", insuranceId, authentication.getName());

        PatientInsuranceResponse response = insuranceService.validateInsuranceDocument(
                patientId, insuranceId, validationComment, authentication.getName());

        return ResponseEntity.ok(response);
    }
}