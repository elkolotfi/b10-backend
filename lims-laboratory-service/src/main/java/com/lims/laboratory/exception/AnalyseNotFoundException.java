package com.lims.laboratory.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class AnalyseNotFoundException extends RuntimeException {

    public AnalyseNotFoundException(String message) {
        super(message);
    }

    public AnalyseNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}