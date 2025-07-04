package com.lims.auth.exception;

public class RateLimitException extends RuntimeException {

    private int remainingAttempts;
    private long resetTimeMillis;

    public RateLimitException(String message) {
        super(message);
    }

    public RateLimitException(String message, int remainingAttempts, long resetTimeMillis) {
        super(message);
        this.remainingAttempts = remainingAttempts;
        this.resetTimeMillis = resetTimeMillis;
    }

    public RateLimitException(String message, Throwable cause) {
        super(message, cause);
    }

    public int getRemainingAttempts() {
        return remainingAttempts;
    }

    public long getResetTimeMillis() {
        return resetTimeMillis;
    }
}
