package com.lims.laboratory.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception levée lors d'erreurs de validation métier
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class LaboratoireValidationException extends RuntimeException {

    public LaboratoireValidationException(String message) {
        super(message);
    }

    public LaboratoireValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}