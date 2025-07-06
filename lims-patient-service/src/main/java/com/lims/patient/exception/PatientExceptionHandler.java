package com.lims.patient.exception;

import com.lims.patient.dto.error.ErrorResponse;
import com.lims.patient.dto.error.FieldError;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.BindException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import jakarta.validation.ConstraintViolationException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Gestionnaire global des exceptions pour le service Patient
 */
@RestControllerAdvice
@Slf4j
public class PatientExceptionHandler {

    @ExceptionHandler(PatientNotFoundException.class)
    public ResponseEntity<ErrorResponse> handlePatientNotFound(
            PatientNotFoundException ex, WebRequest request) {

        log.warn("Patient non trouvé: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .code("PATIENT_NOT_FOUND")
                .message("Patient non trouvé")
                .detail(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .path(request.getDescription(false))
                .build();

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
    }

    @ExceptionHandler(DuplicatePatientException.class)
    public ResponseEntity<ErrorResponse> handleDuplicatePatient(
            DuplicatePatientException ex, WebRequest request) {

        log.warn("Patient en doublon: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .code("DUPLICATE_PATIENT")
                .message("Patient déjà existant")
                .detail(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .path(request.getDescription(false))
                .build();

        return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
    }

    @ExceptionHandler(InvalidPatientDataException.class)
    public ResponseEntity<ErrorResponse> handleInvalidPatientData(
            InvalidPatientDataException ex, WebRequest request) {

        log.warn("Données patient invalides: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .code("INVALID_PATIENT_DATA")
                .message("Données patient invalides")
                .detail(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .path(request.getDescription(false))
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationError(
            MethodArgumentNotValidException ex, WebRequest request) {

        log.warn("Erreur de validation: {}", ex.getMessage());

        List<FieldError> fieldErrors = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> FieldError.builder()
                        .field(error.getField())
                        .rejectedValue(error.getRejectedValue())
                        .message(error.getDefaultMessage())
                        .build())
                .collect(Collectors.toList());

        ErrorResponse error = ErrorResponse.builder()
                .code("VALIDATION_ERROR")
                .message("Erreur de validation des données")
                .detail("Un ou plusieurs champs contiennent des valeurs invalides")
                .timestamp(LocalDateTime.now())
                .path(request.getDescription(false))
                .fieldErrors(fieldErrors)
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(BindException.class)
    public ResponseEntity<ErrorResponse> handleBindError(
            BindException ex, WebRequest request) {

        log.warn("Erreur de binding: {}", ex.getMessage());

        List<FieldError> fieldErrors = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> FieldError.builder()
                        .field(error.getField())
                        .rejectedValue(error.getRejectedValue())
                        .message(error.getDefaultMessage())
                        .build())
                .collect(Collectors.toList());

        ErrorResponse error = ErrorResponse.builder()
                .code("BINDING_ERROR")
                .message("Erreur de liaison des données")
                .detail("Les données fournies ne peuvent pas être traitées")
                .timestamp(LocalDateTime.now())
                .path(request.getDescription(false))
                .fieldErrors(fieldErrors)
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ErrorResponse> handleConstraintViolation(
            ConstraintViolationException ex, WebRequest request) {

        log.warn("Violation de contrainte: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .code("CONSTRAINT_VIOLATION")
                .message("Violation de contrainte de données")
                .detail(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .path(request.getDescription(false))
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(
            AccessDeniedException ex, WebRequest request) {

        log.warn("Accès refusé: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .code("ACCESS_DENIED")
                .message("Accès refusé")
                .detail("Vous n'avez pas les permissions nécessaires pour effectuer cette action")
                .timestamp(LocalDateTime.now())
                .path(request.getDescription(false))
                .build();

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneral(Exception ex, WebRequest request) {
        log.error("Erreur inattendue", ex);

        ErrorResponse error = ErrorResponse.builder()
                .code("INTERNAL_ERROR")
                .message("Erreur interne du serveur")
                .detail("Une erreur inattendue s'est produite")
                .timestamp(LocalDateTime.now())
                .path(request.getDescription(false))
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
}