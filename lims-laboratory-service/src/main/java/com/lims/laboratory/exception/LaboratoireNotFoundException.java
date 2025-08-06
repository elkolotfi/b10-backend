package com.lims.laboratory.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception levée quand un laboratoire n'est pas trouvé
 */
@ResponseStatus(HttpStatus.NOT_FOUND)
public class LaboratoireNotFoundException extends RuntimeException {

    public LaboratoireNotFoundException(String message) {
        super(message);
    }

    public LaboratoireNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}