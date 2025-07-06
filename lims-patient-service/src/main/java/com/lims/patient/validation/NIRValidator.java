package com.lims.patient.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.stereotype.Component;

/**
 * Validateur pour le NIR (Numéro de Sécurité Sociale français)
 * Vérifie le format et la clé de contrôle
 */
@Component
public class NIRValidator implements ConstraintValidator<ValidNIR, String> {

    @Override
    public void initialize(ValidNIR constraintAnnotation) {
        // Initialisation si nécessaire
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.trim().isEmpty()) {
            return false;
        }

        // Suppression des espaces et caractères de formatage
        String nir = value.replaceAll("[\\s-]", "");

        // Vérification du format : 15 chiffres
        if (!nir.matches("^[12][0-9]{12}[0-9]{2}$")) {
            return false;
        }

        // Extraction des parties
        String nirBase = nir.substring(0, 13); // 13 premiers chiffres
        String cleControle = nir.substring(13, 15); // 2 derniers chiffres

        // Calcul de la clé de contrôle
        try {
            long nirNumber = Long.parseLong(nirBase);
            int cleCalculee = 97 - (int)(nirNumber % 97);
            int cleAttendue = Integer.parseInt(cleControle);

            return cleCalculee == cleAttendue;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}