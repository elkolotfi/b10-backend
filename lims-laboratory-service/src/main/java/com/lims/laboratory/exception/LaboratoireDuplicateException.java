package com.lims.laboratory.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception levée quand on tente de créer un laboratoire avec des données déjà existantes
 */
@ResponseStatus(HttpStatus.CONFLICT)
public class LaboratoireDuplicateException extends RuntimeException {

    public LaboratoireDuplicateException(String message) {
        super(message);
    }

    public LaboratoireDuplicateException(String message, Throwable cause) {
        super(message, cause);
    }
}