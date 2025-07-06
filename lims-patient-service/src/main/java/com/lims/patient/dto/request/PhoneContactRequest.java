package com.lims.patient.dto.request;

import com.lims.patient.enums.ContactType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;

/**
 * DTO pour un contact téléphonique
 */
@Builder
public record PhoneContactRequest(
        @NotNull
        ContactType typeContact,

        @NotBlank @Pattern(regexp = "^\\+[1-9][0-9]{7,14}$", message = "Format téléphone invalide (+33...)")
        String numeroTelephone,

        @Pattern(regexp = "^\\+[1-9][0-9]{0,4}$")
        String indicatifPays,

        @Size(max = 10)
        String extension,

        @NotNull
        Boolean estPrincipal,

        // Si c'est un contact d'urgence
        @Size(max = 100)
        String nomContactUrgence,

        @Size(max = 50)
        String relationContact
) {}
