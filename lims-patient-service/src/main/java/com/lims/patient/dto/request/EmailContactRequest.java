package com.lims.patient.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Builder;

/**
 * DTO pour une adresse email
 */
@Builder
public record EmailContactRequest(
        @NotBlank @Email(message = "Format email invalide")
        @Size(max = 255)
        String adresseEmail,

        @NotNull
        Boolean estPrincipal,

        Boolean notificationsResultats,
        Boolean notificationsRdv,
        Boolean notificationsRappels
) {}