package com.lims.patient.converter;

import com.lims.patient.enums.DeliveryMethod;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import lombok.extern.slf4j.Slf4j;

@Converter(autoApply = false)
@Slf4j
public class DeliveryMethodConverter implements AttributeConverter<DeliveryMethod, String> {

    @Override
    public String convertToDatabaseColumn(DeliveryMethod attribute) {
        if (attribute == null) {
            return null;
        }
        log.debug("Converting DeliveryMethod {} to database column", attribute.name());
        return attribute.name();
    }

    @Override
    public DeliveryMethod convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.trim().isEmpty()) {
            return null;
        }

        try {
            DeliveryMethod result = DeliveryMethod.valueOf(dbData.toUpperCase());
            log.debug("Converting database value '{}' to DeliveryMethod {}", dbData, result);
            return result;
        } catch (IllegalArgumentException e) {
            log.warn("Valeur DeliveryMethod inconnue dans la BDD : '{}', utilisation par défaut : EMAIL", dbData);
            return DeliveryMethod.EMAIL;
        }
    }
}