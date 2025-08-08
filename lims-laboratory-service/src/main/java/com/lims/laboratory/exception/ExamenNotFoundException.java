package com.lims.laboratory.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class ExamenNotFoundException extends RuntimeException {
    public ExamenNotFoundException(String message) {
        super(message);
    }

    public ExamenNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}