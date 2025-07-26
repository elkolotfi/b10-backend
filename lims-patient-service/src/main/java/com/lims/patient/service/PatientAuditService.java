package com.lims.patient.service;

import com.lims.patient.dto.response.PatientResponse;
import com.lims.patient.entity.Patient;
import com.lims.patient.entity.PatientAuditLog;
import com.lims.patient.repository.PatientAuditLogRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service d'audit pour tracer toutes les opérations sur les patients
 * Conformité RGPD
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class PatientAuditService {

    private final PatientAuditLogRepository auditLogRepository;

    /**
     * Log un accès général aux données patient
     */
    public void logPatientAccess(UUID patientId, String action, String description,
                                 String performedBy, String userType) {

        PatientAuditLog auditLog = PatientAuditLog.builder()
                .patientId(patientId)
                .action(action)
                .description(description)
                .performedBy(performedBy)
                .performedByType(userType)
                .clientIp(getClientIpAddress())
                .userAgent(getUserAgent())
                .result("SUCCESS")
                .dateAction(LocalDateTime.now())
                .correlationId(UUID.randomUUID())
                .build();

        auditLogRepository.save(auditLog);

        log.info("Audit enregistré: {} - Patient: {} - Utilisateur: {}",
                action, patientId, performedBy);
    }

    /**
     * Log la création d'un patient
     */
    public void logPatientCreation(PatientResponse patient, String createdBy) {
        logPatientAccess(
                UUID.fromString(patient.id()),
                "PATIENT_CREATED",
                String.format("Nouveau patient créé: %s %s", patient.personalInfo().prenom(), patient.personalInfo().nom()),
                createdBy,
                "STAFF"
        );
    }

    /**
     * Log la modification d'un patient
     */
    public void logPatientUpdate(Patient patient, String modifiedBy) {
        logPatientAccess(
                patient.getId(),
                "PATIENT_UPDATED",
                String.format("Patient modifié: %s %s", patient.getFirstName(), patient.getLastName()),
                modifiedBy,
                "STAFF"
        );
    }

    /**
     * Log la suppression d'un patient
     */
    public void logPatientDeletion(Patient patient, String deletedBy) {
        logPatientAccess(
                patient.getId(),
                "PATIENT_DELETED",
                String.format("Patient supprimé (soft delete): %s %s", patient.getFirstName(), patient.getLastName()),
                deletedBy,
                "STAFF"
        );
    }

    /**
     * Récupère l'adresse IP du client
     */
    private String getClientIpAddress() {
        try {
            ServletRequestAttributes attributes =
                    (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            HttpServletRequest request = attributes.getRequest();

            String xForwardedFor = request.getHeader("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                return xForwardedFor.split(",")[0].trim();
            }

            String xRealIp = request.getHeader("X-Real-IP");
            if (xRealIp != null && !xRealIp.isEmpty()) {
                return xRealIp;
            }

            return request.getRemoteAddr();
        } catch (Exception e) {
            log.warn("Impossible de récupérer l'adresse IP", e);
            return "UNKNOWN";
        }
    }

    /**
     * Récupère le User-Agent du client
     */
    private String getUserAgent() {
        try {
            ServletRequestAttributes attributes =
                    (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            HttpServletRequest request = attributes.getRequest();

            return request.getHeader("User-Agent");
        } catch (Exception e) {
            log.warn("Impossible de récupérer le User-Agent", e);
            return "UNKNOWN";
        }
    }
}