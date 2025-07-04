package com.lims.auth.exception;

public class AdminNotFoundException extends RuntimeException {

    private String adminId;
    private String email;

    public AdminNotFoundException(String message) {
        super(message);
    }

    public AdminNotFoundException(String message, String adminId) {
        super(message);
        this.adminId = adminId;
    }

    public AdminNotFoundException(String message, String adminId, String email) {
        super(message);
        this.adminId = adminId;
        this.email = email;
    }

    public AdminNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public String getAdminId() {
        return adminId;
    }

    public String getEmail() {
        return email;
    }
}