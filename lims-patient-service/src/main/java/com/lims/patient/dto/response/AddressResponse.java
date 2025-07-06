package com.lims.patient.dto.response;

import com.lims.patient.enums.AddressType;
import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record AddressResponse(
        String id,
        AddressType typeAdresse,
        String ligne1,
        String ligne2,
        String codePostal,
        String ville,
        String departement,
        String region,
        String pays,
        Boolean estPrincipale,
        Boolean estValide,
        LocalDateTime dateValidation
) {}
