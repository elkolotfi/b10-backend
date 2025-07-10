package com.lims.patient.dto.response;

import com.lims.patient.enums.DeliveryMethod;
import com.lims.patient.enums.NotificationPreference;
import lombok.Builder;

import java.math.BigDecimal;

/**
 * DTO de réponse pour les informations de contact
 */
@Builder
public record ContactInfoResponse(
        String email,
        String telephone,
        String adresseComplete,
        String adresseLigne1,
        String adresseLigne2,
        String codePostal,
        String ville,
        String departement,
        String region,
        String pays,
        BigDecimal latitude,
        BigDecimal longitude,
        DeliveryMethod methodeLivraisonPreferee,
        NotificationPreference preferenceNotification,
        String languePreferee,
        Boolean notificationsResultats,
        Boolean notificationsRdv,
        Boolean notificationsRappels
) {}
