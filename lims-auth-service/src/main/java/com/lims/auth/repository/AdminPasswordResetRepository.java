package com.lims.auth.repository;

import com.lims.auth.entity.AdminPasswordReset;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface AdminPasswordResetRepository extends JpaRepository<AdminPasswordReset, Long> {

    Optional<AdminPasswordReset> findByTokenAndUsedFalse(String token);

    List<AdminPasswordReset> findByAdminUserIdOrderByCreatedAtDesc(String adminUserId);

    @Query("SELECT r FROM AdminPasswordReset r WHERE r.token = :token AND r.used = false AND r.expiresAt > :now")
    Optional<AdminPasswordReset> findValidToken(@Param("token") String token, @Param("now") LocalDateTime now);

    @Query("SELECT r FROM AdminPasswordReset r WHERE r.adminUser.id = :adminUserId AND r.used = false AND r.expiresAt > :now")
    List<AdminPasswordReset> findValidTokensForUser(@Param("adminUserId") String adminUserId, @Param("now") LocalDateTime now);

    @Query("SELECT r FROM AdminPasswordReset r WHERE r.expiresAt < :now AND r.used = false")
    List<AdminPasswordReset> findExpiredTokens(@Param("now") LocalDateTime now);

    @Modifying
    @Query("UPDATE AdminPasswordReset r SET r.used = true, r.usedAt = :usedAt WHERE r.token = :token")
    int markTokenAsUsed(@Param("token") String token, @Param("usedAt") LocalDateTime usedAt);

    @Modifying
    @Query("UPDATE AdminPasswordReset r SET r.used = true, r.usedAt = :usedAt WHERE r.adminUser.id = :adminUserId AND r.used = false")
    int markAllUserTokensAsUsed(@Param("adminUserId") String adminUserId, @Param("usedAt") LocalDateTime usedAt);

    @Query("SELECT COUNT(r) FROM AdminPasswordReset r WHERE r.adminUser.id = :adminUserId AND r.createdAt > :threshold")
    long countRecentRequestsByUser(@Param("adminUserId") String adminUserId, @Param("threshold") LocalDateTime threshold);

    @Query("SELECT COUNT(r) FROM AdminPasswordReset r WHERE r.clientIp = :clientIp AND r.createdAt > :threshold")
    long countRecentRequestsByIp(@Param("clientIp") String clientIp, @Param("threshold") LocalDateTime threshold);

    void deleteByCreatedAtBeforeAndUsedTrue(LocalDateTime threshold);

    void deleteByExpiresAtBeforeAndUsedFalse(LocalDateTime threshold);
}