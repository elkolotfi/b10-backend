package com.lims.patient.dto.response;

import com.lims.patient.enums.DeliveryMethod;
import com.lims.patient.enums.NotificationPreference;
import lombok.Builder;

import java.util.List;

@Builder
public record ContactInfoResponse(
        List<PhoneContactResponse> telephones,
        List<EmailContactResponse> emails,
        List<AddressResponse> adresses,
        DeliveryMethod methodeLivraisonPreferee,
        NotificationPreference preferenceNotification
) {}
