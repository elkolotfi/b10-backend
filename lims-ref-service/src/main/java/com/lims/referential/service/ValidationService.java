package com.lims.referential.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
@Slf4j
public class ValidationService {

    private static final Pattern RPPS_PATTERN = Pattern.compile("^\\d{11}$");
    private static final Pattern NABM_PATTERN = Pattern.compile("^[A-Z]\\d{3}$");
    private static final Pattern CODE_POSTAL_PATTERN = Pattern.compile("^\\d{5}$");

    public Map<String, Object> validateRpps(String numeroRpps) {
        log.debug("Validation du numéro RPPS: {}", numeroRpps);

        boolean isValid = numeroRpps != null && RPPS_PATTERN.matcher(numeroRpps).matches();

        return Map.of(
                "numeroRpps", numeroRpps,
                "isValid", isValid,
                "format", "11 chiffres",
                "message", isValid ? "Numéro RPPS valide" : "Numéro RPPS invalide - doit contenir exactement 11 chiffres"
        );
    }

    public Map<String, Object> validateNabm(String codeNabm) {
        log.debug("Validation du code NABM: {}", codeNabm);

        boolean isValid = codeNabm != null && NABM_PATTERN.matcher(codeNabm).matches();

        return Map.of(
                "codeNabm", codeNabm,
                "isValid", isValid,
                "format", "1 lettre + 3 chiffres",
                "message", isValid ? "Code NABM valide" : "Code NABM invalide - format attendu: 1 lettre suivie de 3 chiffres (ex: B145)"
        );
    }

    public Map<String, Object> validateCodePostal(String codePostal, String ville) {
        log.debug("Validation du code postal: {} pour la ville: {}", codePostal, ville);

        boolean isValidFormat = codePostal != null && CODE_POSTAL_PATTERN.matcher(codePostal).matches();

        // TODO: Ajouter une validation avec la base géographique
        boolean isValidWithVille = isValidFormat; // Pour l'instant, seulement le format

        return Map.of(
                "codePostal", codePostal,
                "ville", ville,
                "isValidFormat", isValidFormat,
                "isValidWithVille", isValidWithVille,
                "format", "5 chiffres",
                "message", isValidFormat ? "Code postal valide" : "Code postal invalide - doit contenir exactement 5 chiffres"
        );
    }
}