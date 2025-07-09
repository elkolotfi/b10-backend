package com.lims.patient.controller;

import com.lims.patient.security.PatientSecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Contrôleur pour la gestion des patients avec sécurité multi-realms
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/patients")
@RequiredArgsConstructor
public class PatientController {

    private final PatientSecurityContext securityContext;
    // private final PatientService patientService; // À injecter

    /**
     * Récupère un patient par son ID
     * Accessible par :
     * - Admins (tous les patients)
     * - Patients (leurs propres données uniquement)
     * - Staff (patients de leur laboratoire)
     */
    @GetMapping("/{patientId}")
    @PreAuthorize("@patientSecurityContext.canAccessPatient(#patientId)")
    public ResponseEntity<?> getPatient(@PathVariable("patientId") UUID patientId) {
        log.info("GET /patients/{} requested by user: {} ({})",
                patientId,
                securityContext.getCurrentUserId(),
                securityContext.getCurrentUserType());

        // Log des informations de sécurité pour debug
        logSecurityContext();

        // Vérification supplémentaire au niveau métier
        if (!securityContext.canAccessPatient(patientId)) {
            log.warn("Access denied for user {} to patient {}",
                    securityContext.getCurrentUserId(), patientId);
            return ResponseEntity.status(403).body("Access denied to this patient data");
        }

        // Simulation de récupération des données patient
        return ResponseEntity.ok().body("""
            {
                "patientId": "%s",
                "message": "Patient data retrieved successfully",
                "accessedBy": "%s",
                "userType": "%s",
                "realm": "%s"
            }
            """.formatted(
                patientId,
                securityContext.getCurrentUserId(),
                securityContext.getCurrentUserType(),
                securityContext.getCurrentUserRealm()
        ));
    }

    /**
     * Liste tous les patients
     * Accessible uniquement par les admins et le staff
     */
    @GetMapping
    @PreAuthorize("@patientSecurityContext.canReadAllPatients()")
    public ResponseEntity<?> getAllPatients() {
        log.info("GET /patients requested by user: {} ({})",
                securityContext.getCurrentUserId(),
                securityContext.getCurrentUserType());

        logSecurityContext();

        return ResponseEntity.ok().body("""
            {
                "message": "Patients list retrieved successfully",
                "accessedBy": "%s",
                "userType": "%s",
                "realm": "%s",
                "laboratoryId": "%s"
            }
            """.formatted(
                securityContext.getCurrentUserId(),
                securityContext.getCurrentUserType(),
                securityContext.getCurrentUserRealm(),
                securityContext.getCurrentUserLaboratoryId()
        ));
    }

    /**
     * Crée un nouveau patient
     * Accessible par les admins et le staff autorisé
     */
    @PostMapping
    @PreAuthorize("@patientSecurityContext.canWritePatient()")
    public ResponseEntity<?> createPatient(@RequestBody Object patientData) {
        log.info("POST /patients requested by user: {} ({})",
                securityContext.getCurrentUserId(),
                securityContext.getCurrentUserType());

        logSecurityContext();

        return ResponseEntity.ok().body("""
            {
                "message": "Patient created successfully",
                "createdBy": "%s",
                "userType": "%s",
                "realm": "%s"
            }
            """.formatted(
                securityContext.getCurrentUserId(),
                securityContext.getCurrentUserType(),
                securityContext.getCurrentUserRealm()
        ));
    }

    /**
     * Met à jour un patient
     * Accessible par les admins et le staff autorisé
     */
    @PutMapping("/{patientId}")
    @PreAuthorize("@patientSecurityContext.canWritePatient() and @patientSecurityContext.canAccessPatient(#patientId)")
    public ResponseEntity<?> updatePatient(@PathVariable UUID patientId, @RequestBody Object patientData) {
        log.info("PUT /patients/{} requested by user: {} ({})",
                patientId,
                securityContext.getCurrentUserId(),
                securityContext.getCurrentUserType());

        logSecurityContext();

        return ResponseEntity.ok().body("""
            {
                "patientId": "%s",
                "message": "Patient updated successfully",
                "updatedBy": "%s",
                "userType": "%s",
                "realm": "%s"
            }
            """.formatted(
                patientId,
                securityContext.getCurrentUserId(),
                securityContext.getCurrentUserType(),
                securityContext.getCurrentUserRealm()
        ));
    }

    /**
     * Supprime un patient
     * Accessible uniquement par les admins
     */
    @DeleteMapping("/{patientId}")
    @PreAuthorize("@patientSecurityContext.canDeletePatient()")
    public ResponseEntity<?> deletePatient(@PathVariable UUID patientId) {
        log.info("DELETE /patients/{} requested by user: {} ({})",
                patientId,
                securityContext.getCurrentUserId(),
                securityContext.getCurrentUserType());

        logSecurityContext();

        return ResponseEntity.ok().body("""
            {
                "patientId": "%s",
                "message": "Patient deleted successfully",
                "deletedBy": "%s",
                "userType": "%s",
                "realm": "%s"
            }
            """.formatted(
                patientId,
                securityContext.getCurrentUserId(),
                securityContext.getCurrentUserType(),
                securityContext.getCurrentUserRealm()
        ));
    }

    /**
     * Endpoint pour récupérer les informations de l'utilisateur connecté
     * Accessible par tous les utilisateurs authentifiés
     */
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser() {
        log.info("GET /patients/me requested by user: {} ({})",
                securityContext.getCurrentUserId(),
                securityContext.getCurrentUserType());

        logSecurityContext();

        return ResponseEntity.ok().body("""
            {
                "userId": "%s",
                "email": "%s",
                "userType": "%s",
                "role": "%s",
                "realm": "%s",
                "laboratoryId": "%s",
                "patientId": "%s"
            }
            """.formatted(
                securityContext.getCurrentUserId(),
                securityContext.getCurrentUserEmail(),
                securityContext.getCurrentUserType(),
                securityContext.getCurrentUserRole(),
                securityContext.getCurrentUserRealm(),
                securityContext.getCurrentUserLaboratoryId(),
                securityContext.getCurrentPatientId()
        ));
    }

    /**
     * Log détaillé du contexte de sécurité pour le debug
     */
    private void logSecurityContext() {
        if (log.isDebugEnabled()) {
            log.debug("=== Security Context ===");
            log.debug("User ID: {}", securityContext.getCurrentUserId());
            log.debug("Email: {}", securityContext.getCurrentUserEmail());
            log.debug("User Type: {}", securityContext.getCurrentUserType());
            log.debug("Role: {}", securityContext.getCurrentUserRole());
            log.debug("Realm: {}", securityContext.getCurrentUserRealm());
            log.debug("Laboratory ID: {}", securityContext.getCurrentUserLaboratoryId());
            log.debug("Patient ID: {}", securityContext.getCurrentPatientId());
            log.debug("Is Admin: {}", securityContext.isCurrentUserAdmin());
            log.debug("Is Patient: {}", securityContext.isCurrentUserPatient());
            log.debug("Is Staff: {}", securityContext.isCurrentUserStaff());
            log.debug("Can Read All Patients: {}", securityContext.canReadAllPatients());
            log.debug("Can Write Patient: {}", securityContext.canWritePatient());
            log.debug("Can Delete Patient: {}", securityContext.canDeletePatient());
            log.debug("========================");
        }
    }

    /*@PostConstruct
    public void debugJwt() {
        JwtDebugTool.debugJwtDecoding();
    }*/
}