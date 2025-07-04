package com.lims.auth.exception;

public class InvalidMfaCodeException extends MfaException {

    private int remainingAttempts;
    private boolean isBackupCode;

    public InvalidMfaCodeException(String message) {
        super(message);
    }

    public InvalidMfaCodeException(String message, int remainingAttempts) {
        super(message);
        this.remainingAttempts = remainingAttempts;
    }

    public InvalidMfaCodeException(String message, int remainingAttempts, boolean isBackupCode) {
        super(message);
        this.remainingAttempts = remainingAttempts;
        this.isBackupCode = isBackupCode;
    }

    public InvalidMfaCodeException(String message, Throwable cause) {
        super(message, cause);
    }

    public int getRemainingAttempts() {
        return remainingAttempts;
    }

    public boolean isBackupCode() {
        return isBackupCode;
    }
}
