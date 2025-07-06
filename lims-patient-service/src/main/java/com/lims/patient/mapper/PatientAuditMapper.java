package com.lims.patient.mapper;

import com.lims.patient.dto.response.AuditLogResponse;
import com.lims.patient.entity.PatientAuditLog;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;

import java.util.List;

/**
 * Mapper pour les logs d'audit
 */
@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.IGNORE
)
public interface PatientAuditMapper {

    @Mapping(target = "patientId", source = "patientId", qualifiedByName = "uuidToString")
    @Mapping(target = "correlationId", source = "correlationId", qualifiedByName = "uuidToString")
    AuditLogResponse toAuditLogResponse(PatientAuditLog auditLog);

    List<AuditLogResponse> toAuditLogResponseList(List<PatientAuditLog> auditLogs);

    @org.mapstruct.Named("uuidToString")
    default String uuidToString(java.util.UUID uuid) {
        return uuid != null ? uuid.toString() : null;
    }
}