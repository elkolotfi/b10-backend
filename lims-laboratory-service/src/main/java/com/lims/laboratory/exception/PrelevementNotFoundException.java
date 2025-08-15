package com.lims.laboratory.exception;

/**
 * Exception levée quand un prélèvement demandé n'est pas trouvé
 */
public class PrelevementNotFoundException extends RuntimeException {

    public PrelevementNotFoundException(String message) {
        super(message);
    }

    public PrelevementNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}