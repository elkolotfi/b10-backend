package com.lims.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "lims.auth")
@Data
public class LimsAuthProperties {

    private Mfa mfa = new Mfa();
    private RateLimit rateLimit = new RateLimit();
    private Session session = new Session();
    private Security security = new Security();
    private Jwt jwt = new Jwt();

    @Data
    public static class Mfa {
        private String issuer = "LIMS-Admin-System";
        private BackupCodes backupCodes = new BackupCodes();
        private int setupTokenExpiry = 600; // 10 minutes
        private int resetTokenExpiry = 86400; // 24 heures

        @Data
        public static class BackupCodes {
            private int count = 10;
            private int length = 8;
        }
    }

    @Data
    public static class RateLimit {
        private int maxAttempts = 5;
        private int windowMinutes = 15;
        private int lockoutDurationMinutes = 30;
    }

    @Data
    public static class Session {
        private int timeout = 7200; // 2 heures
        private boolean extendOnActivity = true;
        private int maxConcurrentSessions = 3;
        private int cleanupIntervalMinutes = 60;
    }

    @Data
    public static class Security {
        private int maxFailedAttempts = 3;
        private int lockoutDurationMinutes = 30;
        private int passwordResetTokenExpiry = 86400; // 24 heures
        private int maxPasswordResetRequests = 3;
        private int passwordResetCooldownMinutes = 60;
    }

    @Data
    public static class Jwt {
        private String secret = "default-secret-key-for-development-only-change-in-production";
        private int accessTokenValidity = 3600; // 1 heure
        private int refreshTokenValidity = 86400; // 24 heures
        private String issuer = "lims-auth-service";
    }
}