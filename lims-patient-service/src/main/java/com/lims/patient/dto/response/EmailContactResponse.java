package com.lims.patient.dto.response;

import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record EmailContactResponse(
        String id,
        String adresseEmail,
        Boolean estPrincipal,
        Boolean estValide,
        LocalDateTime dateValidation,
        Boolean notificationsResultats,
        Boolean notificationsRdv,
        Boolean notificationsRappels
) {}
