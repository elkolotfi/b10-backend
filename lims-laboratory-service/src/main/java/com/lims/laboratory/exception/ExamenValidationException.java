package com.lims.laboratory.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class ExamenValidationException extends RuntimeException {
    public ExamenValidationException(String message) {
        super(message);
    }

    public ExamenValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}