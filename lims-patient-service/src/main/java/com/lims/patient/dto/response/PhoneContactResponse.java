package com.lims.patient.dto.response;

import com.lims.patient.enums.ContactType;
import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record PhoneContactResponse(
        String id,
        ContactType typeContact,
        String numeroTelephone,
        String indicatifPays,
        String extension,
        Boolean estPrincipal,
        Boolean estValide,
        LocalDateTime dateValidation,
        String nomContactUrgence,
        String relationContact
) {}
