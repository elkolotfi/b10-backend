package com.lims.patient.dto.response;

import lombok.Builder;
import java.util.List;

@Builder
public record PatientSpecificitiesResponse(
        List<String> specificityIds
) {}