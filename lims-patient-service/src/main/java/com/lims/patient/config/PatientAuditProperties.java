package com.lims.patient.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "lims.patient.audit")
public class PatientAuditProperties {
    private Boolean enabled = true;
    private Boolean logAllAccess = true;
    private Integer retentionDays = 2555;
    private Boolean includeIpAddress = true;
    private Boolean includeUserAgent = true;
}