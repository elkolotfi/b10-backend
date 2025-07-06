package com.lims.patient.dto.request;

import com.lims.patient.enums.DeliveryMethod;
import com.lims.patient.enums.NotificationPreference;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import lombok.Builder;

import java.util.List;

/**
 * DTO pour les informations de contact
 */
@Builder
public record ContactInfoRequest(
        @Valid @NotEmpty(message = "Au moins un contact téléphonique est requis")
        List<PhoneContactRequest> telephones,

        @Valid @NotEmpty(message = "Au moins une adresse email est requise")
        List<EmailContactRequest> emails,

        @Valid @NotEmpty(message = "Au moins une adresse postale est requise")
        List<AddressRequest> adresses,

        DeliveryMethod methodeLivraisonPreferee,
        NotificationPreference preferenceNotification
) {}

