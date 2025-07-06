package com.lims.patient.dto.request;

import com.lims.patient.enums.DeliveryMethod;
import com.lims.patient.enums.NotificationPreference;
import lombok.Builder;

import java.util.List;

@Builder
public record ContactInfoUpdateRequest(
        List<PhoneContactRequest> telephones,
        List<EmailContactRequest> emails,
        List<AddressRequest> adresses,
        DeliveryMethod methodeLivraisonPreferee,
        NotificationPreference preferenceNotification
) {}
