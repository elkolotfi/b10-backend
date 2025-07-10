package com.lims.patient.dto.request;

import com.lims.patient.enums.DeliveryMethod;
import com.lims.patient.enums.NotificationPreference;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;

import java.math.BigDecimal;

/**
 * DTO pour la mise à jour des informations de contact
 */
@Builder
public record ContactInfoUpdateRequest(
        @Email @Size(max = 255)
        String email,

        @Pattern(regexp = "^\\+[1-9][0-9]{8,14}$", message = "Format téléphone invalide")
        String telephone,

        @Size(max = 255)
        String adresseLigne1,

        @Size(max = 255)
        String adresseLigne2,

        @Pattern(regexp = "^[0-9]{5}$", message = "Code postal invalide")
        String codePostal,

        @Size(max = 100)
        String ville,

        @Size(max = 100)
        String departement,

        @Size(max = 100)
        String region,

        @Size(max = 100)
        String pays,

        BigDecimal latitude,

        BigDecimal longitude,

        DeliveryMethod methodeLivraisonPreferee,

        NotificationPreference preferenceNotification,

        @Size(max = 5)
        String languePreferee,

        Boolean notificationsResultats,

        Boolean notificationsRdv,

        Boolean notificationsRappels
) {}
