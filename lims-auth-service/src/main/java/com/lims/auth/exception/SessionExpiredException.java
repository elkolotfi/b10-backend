package com.lims.auth.exception;

import java.time.LocalDateTime;

public class SessionExpiredException extends RuntimeException {

    private String sessionId;
    private LocalDateTime expiredAt;

    public SessionExpiredException(String message) {
        super(message);
    }

    public SessionExpiredException(String message, String sessionId) {
        super(message);
        this.sessionId = sessionId;
    }

    public SessionExpiredException(String message, String sessionId, LocalDateTime expiredAt) {
        super(message);
        this.sessionId = sessionId;
        this.expiredAt = expiredAt;
    }

    public SessionExpiredException(String message, Throwable cause) {
        super(message, cause);
    }

    public String getSessionId() {
        return sessionId;
    }

    public LocalDateTime getExpiredAt() {
        return expiredAt;
    }
}