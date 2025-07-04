package com.lims.auth.exception;

import java.time.LocalDateTime;

public class AccountLockedException extends RuntimeException {

    private LocalDateTime lockedUntil;
    private int failedAttempts;

    public AccountLockedException(String message) {
        super(message);
    }

    public AccountLockedException(String message, LocalDateTime lockedUntil) {
        super(message);
        this.lockedUntil = lockedUntil;
    }

    public AccountLockedException(String message, LocalDateTime lockedUntil, int failedAttempts) {
        super(message);
        this.lockedUntil = lockedUntil;
        this.failedAttempts = failedAttempts;
    }

    public AccountLockedException(String message, Throwable cause) {
        super(message, cause);
    }

    public LocalDateTime getLockedUntil() {
        return lockedUntil;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }
}