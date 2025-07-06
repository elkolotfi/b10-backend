package com.lims.patient.dto.request;

import com.lims.patient.enums.AddressType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Builder;

/**
 * DTO pour une adresse postale
 */
@Builder
public record AddressRequest(
        @NotNull
        AddressType typeAdresse,

        @NotBlank @Size(max = 255)
        String ligne1,

        @Size(max = 255)
        String ligne2,

        @NotBlank @Size(min = 5, max = 10)
        String codePostal,

        @NotBlank @Size(max = 100)
        String ville,

        @Size(max = 100)
        String departement,

        @Size(max = 100)
        String region,

        @NotBlank @Size(max = 50)
        String pays,

        @NotNull
        Boolean estPrincipale
) {}
