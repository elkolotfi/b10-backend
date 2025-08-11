package com.lims.laboratory.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class AnalyseDuplicateException extends RuntimeException {

    public AnalyseDuplicateException(String message) {
        super(message);
    }

    public AnalyseDuplicateException(String message, Throwable cause) {
        super(message, cause);
    }
}