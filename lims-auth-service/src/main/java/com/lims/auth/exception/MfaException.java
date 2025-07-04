// MfaException.java
package com.lims.auth.exception;

public class MfaException extends RuntimeException {

    private String errorCode;

    public MfaException(String message) {
        super(message);
    }

    public MfaException(String message, Throwable cause) {
        super(message, cause);
    }

    public MfaException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public MfaException(String message, String errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
