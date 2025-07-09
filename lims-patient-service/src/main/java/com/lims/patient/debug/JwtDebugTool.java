package com.lims.patient.debug;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Outil de debug pour tester le décodage JWT
 * À supprimer après résolution du problème
 */
@Slf4j
public class JwtDebugTool {

    public static void debugJwtDecoding() {
        String token = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzdXBlci1hZG1pbi1kZXYtMDAxIiwidXNlcl90eXBlIjoiQURNSU4iLCJyb2xlIjoiU1VQRVJfQURNSU4iLCJtZmFfdmVyaWZpZWQiOnRydWUsInBlcm1pc3Npb25zIjpbIkFVRElUX1JFQUQiLCJDT05GSUdVUkFUSU9OX1dSSVRFIiwiU1lTVEVNX0FETUlOIiwiVVNFUl9NQU5BR0VNRU5UIl0sInNlc3Npb25faWQiOiIwMjZiNjEyOS03YzZjLTRkZjctOGM1YS02ZWJjMzc5OGY2M2UiLCJyZWFsbSI6ImxpbXMtYWRtaW4iLCJleHAiOjE3NTIwOTc3NDUsImlhdCI6MTc1MjA5NDE0NSwiZW1haWwiOiJzdXBlcmFkbWluQGxpbXMubG9jYWwiLCJpc3MiOiJsaW1zLWF1dGgtc2VydmljZSJ9.MawaHKIVh1Z3Uw8q7EQ-2MMnBYiSNtxEjIc-qELyk1TDtfceymHfGFsQz8_hpTO2PG9Mr9d9WtP8AhBYzFr6vw";
        String secret = "G9/BrPDMezKO3cxercRPm7OtvRjWGOeONQCk7AjB6s+pttEuco8xcUEE6dT2IHNHix9aNk4i+c1N8CaTTp84WxCfZMCC/UVJABajwU4ToymMJ/9gT3uxMK5PqrJcCHNi2cUo3P9k+ZaBCqvqwcDZv6kY7mdaz6G5VmcWAU8+4OgZVZEssNvY2kTInV2Sz4JZzp4/N8aWGf6ml3C+q4I8l0Yk9qImvqnAeMX83Rxp3R+yLk2LvCuaYx1lEkSbkM2NbsN1W8ebtZwxMC0CpeLY57V7DocrjvK7v/pjHHUu27qad1JgLBhmoNy4LZX1rqLSKdYvjGQqQd8SU4vP311d9fY8rv47DLKjSPKkee4XTtrfTfH1fh3mnPjYl2NoZjCzr7KAHB3lKpk56rUlmXYbqqExOlDGmnXOrnCL5JRj3LWgwvw6sR73/CGsigxkZvks00QF48cSfJPgFT+TdZ4FyAxc9vC+MG5FDdSjG+wCgmJ/UYQ9MOdLhNGs2itMpf3mN/z81/JYbbDxrNWPah56Ybr8Y4DUykgfJLMgiK/nwME5/qwjzkfRpjEMBRaZbIJPy7N+NfdgIolVjdNj6eBNUHLlrerV2G5FcEkHTsYrTIFrhxxAI3gE3KI92pBPBXxKohXrvVt4nupaj9onnzfP/y5s5kQkNUomVQYMIbyUKGU=";

        log.info("=== JWT DEBUG TOOL ===");
        log.info("Testing JWT decoding with different key formats");

        // Test 1: Base64 décodage
        try {
            byte[] keyBytes = Base64.getDecoder().decode(secret);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "HmacSHA512");

            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            log.info("✅ SUCCESS with Base64 decoded key!");
            log.info("Subject: {}", claims.getSubject());
            log.info("Realm: {}", claims.get("realm"));
            log.info("User type: {}", claims.get("user_type"));
            return;
        } catch (Exception e) {
            log.error("❌ Base64 decoding failed: {}", e.getMessage());
        }

        // Test 2: Clé brute
        try {
            SecretKeySpec secretKey = new SecretKeySpec(
                    secret.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA512"
            );

            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            log.info("✅ SUCCESS with raw string key!");
            log.info("Subject: {}", claims.getSubject());
            log.info("Realm: {}", claims.get("realm"));
            log.info("User type: {}", claims.get("user_type"));
        } catch (Exception e) {
            log.error("❌ Raw string decoding failed: {}", e.getMessage());
        }

        // Test 3: Informations sur la clé
        try {
            log.info("Secret key length: {} characters", secret.length());
            log.info("Secret key (first 50 chars): {}", secret.substring(0, Math.min(50, secret.length())));

            if (isBase64(secret)) {
                byte[] decoded = Base64.getDecoder().decode(secret);
                log.info("Base64 decoded length: {} bytes", decoded.length);
            } else {
                log.info("Secret is not valid Base64");
            }
        } catch (Exception e) {
            log.error("Error analyzing secret: {}", e.getMessage());
        }
    }

    private static boolean isBase64(String str) {
        try {
            Base64.getDecoder().decode(str);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}