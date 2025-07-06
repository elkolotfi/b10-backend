package com.lims.patient.dto.response;

import java.time.LocalDateTime;

/**
 * DTO de réponse pour les logs d'audit
 */
public record AuditLogResponse(
        Long id,
        String patientId,
        String action,
        String description,
        String tableConcernee,
        String idEnregistrement,
        String performedBy,
        String performedByType,
        String realmUtilisateur,
        String clientIp,
        String userAgent,
        String sessionId,
        String anciennesValeurs,
        String nouvellesValeurs,
        String result,
        String messageErreur,
        LocalDateTime dateAction,
        String correlationId
) {}