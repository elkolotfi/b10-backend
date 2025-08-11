package com.lims.laboratory.exception;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Gestionnaire global des exceptions pour les laboratoires
 */
@RestControllerAdvice
@Slf4j
public class LaboratoireExceptionHandler {

    /**
     * Gestion des erreurs de laboratoire non trouvé
     */
    @ExceptionHandler(ExamenNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleLaboratoireNotFound(ExamenNotFoundException ex) {
        log.warn("Excamen non trouvé: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.NOT_FOUND.value())
                .error("Laboratoire non trouvé")
                .message(ex.getMessage())
                .path("/api/v1/laboratoires")
                .build();

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
    }

    /**
     * Gestion des erreurs de laboratoire non trouvé
     */
    @ExceptionHandler(LaboratoireNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleLaboratoireNotFound(LaboratoireNotFoundException ex) {
        log.warn("Laboratoire non trouvé: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.NOT_FOUND.value())
                .error("Laboratoire non trouvé")
                .message(ex.getMessage())
                .path("/api/v1/laboratoires")
                .build();

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
    }

    /**
     * Gestion des erreurs de duplication
     */
    @ExceptionHandler(LaboratoireDuplicateException.class)
    public ResponseEntity<ErrorResponse> handleLaboratoireDuplicate(LaboratoireDuplicateException ex) {
        log.warn("Duplication de laboratoire: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.CONFLICT.value())
                .error("Données dupliquées")
                .message(ex.getMessage())
                .path("/api/v1/laboratoires")
                .build();

        return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
    }

    /**
     * Gestion des erreurs de validation métier
     */
    @ExceptionHandler(LaboratoireValidationException.class)
    public ResponseEntity<ErrorResponse> handleLaboratoireValidation(LaboratoireValidationException ex) {
        log.warn("Erreur de validation: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Erreur de validation")
                .message(ex.getMessage())
                .path("/api/v1/laboratoires")
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    /**
     * Gestion des erreurs de validation des annotations Bean Validation
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ValidationErrorResponse> handleValidationExceptions(MethodArgumentNotValidException ex) {
        log.warn("Erreurs de validation des champs: {}", ex.getMessage());

        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        ValidationErrorResponse errorResponse = ValidationErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Erreurs de validation")
                .message("Les données fournies ne respectent pas les contraintes de validation")
                .path("/api/v1/laboratoires")
                .fieldErrors(errors)
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

    /**
     * Gestion des erreurs de contraintes de validation
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ValidationErrorResponse> handleConstraintViolation(ConstraintViolationException ex) {
        log.warn("Violations de contraintes: {}", ex.getMessage());

        Map<String, String> errors = new HashMap<>();
        for (ConstraintViolation<?> violation : ex.getConstraintViolations()) {
            String fieldName = violation.getPropertyPath().toString();
            String errorMessage = violation.getMessage();
            errors.put(fieldName, errorMessage);
        }

        ValidationErrorResponse errorResponse = ValidationErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Violations de contraintes")
                .message("Les données ne respectent pas les contraintes définies")
                .path("/api/v1/laboratoires")
                .fieldErrors(errors)
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

    /**
     * Gestion des erreurs génériques
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(Exception ex) {
        log.error("Erreur inattendue: ", ex);

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .error("Erreur interne du serveur")
                .message("Une erreur inattendue s'est produite")
                .path("/api/v1/laboratoires")
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }

    @ExceptionHandler(AuthorizationDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAuthorizationDenied(AuthorizationDeniedException ex, WebRequest request) {
        log.warn("Accès refusé - Autorisation insuffisante: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.FORBIDDEN.value())
                .error("Accès refusé")
                .message("Vous n'avez pas les autorisations nécessaires pour effectuer cette action")
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ErrorResponse> handleMissingRequestParameter(MissingServletRequestParameterException ex, WebRequest request) {
        log.warn("Paramètre de requête manquant: {} de type {}", ex.getParameterName(), ex.getParameterType());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Paramètre manquant")
                .message(String.format("Le paramètre '%s' de type '%s' est requis", ex.getParameterName(), ex.getParameterType()))
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(AnalyseNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleAnalyseNotFound(AnalyseNotFoundException ex) {
        log.warn("Analyse non trouvée: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .status(HttpStatus.NOT_FOUND.value())
                .error("ANALYSE_NOT_FOUND")
                .message(ex.getMessage())
                .timestamp(Instant.now())
                .build();

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
    }

    @ExceptionHandler(AnalyseDuplicateException.class)
    public ResponseEntity<ErrorResponse> handleAnalyseDuplicate(AnalyseDuplicateException ex) {
        log.warn("Conflit analyse: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .status(HttpStatus.CONFLICT.value())
                .error("ANALYSE_DUPLICATE")
                .message(ex.getMessage())
                .timestamp(Instant.now())
                .build();

        return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
    }

    // === Classes de réponse d'erreur ===

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ErrorResponse {
        private Instant timestamp;
        private int status;
        private String error;
        private String message;
        private String path;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ValidationErrorResponse {
        private Instant timestamp;
        private int status;
        private String error;
        private String message;
        private String path;
        private Map<String, String> fieldErrors;
    }
}