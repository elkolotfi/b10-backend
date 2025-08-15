package com.lims.laboratory.exception;

/**
 * Exception levée quand on tente de créer un prélèvement en doublon
 */
public class PrelevementDuplicateException extends RuntimeException {

    public PrelevementDuplicateException(String message) {
        super(message);
    }

    public PrelevementDuplicateException(String message, Throwable cause) {
        super(message, cause);
    }
}