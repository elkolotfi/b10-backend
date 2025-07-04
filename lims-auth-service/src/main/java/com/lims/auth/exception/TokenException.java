package com.lims.auth.exception;

public class TokenException extends RuntimeException {

    private String tokenType;
    private String errorCode;

    public TokenException(String message) {
        super(message);
    }

    public TokenException(String message, String tokenType) {
        super(message);
        this.tokenType = tokenType;
    }

    public TokenException(String message, String tokenType, String errorCode) {
        super(message);
        this.tokenType = tokenType;
        this.errorCode = errorCode;
    }

    public TokenException(String message, Throwable cause) {
        super(message, cause);
    }

    public String getTokenType() {
        return tokenType;
    }

    public String getErrorCode() {
        return errorCode;
    }
}