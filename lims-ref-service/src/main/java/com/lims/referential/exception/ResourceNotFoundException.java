package com.lims.referential.exception;

/**
 * Exception lancée quand une ressource n'est pas trouvée
 */
public class ResourceNotFoundException extends RuntimeException {

    public ResourceNotFoundException(String message) {
        super(message);
    }

    public ResourceNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public ResourceNotFoundException(String resourceType, String identifier) {
        super(String.format("%s non trouvé avec l'identifiant: %s", resourceType, identifier));
    }
}