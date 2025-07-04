package com.lims.auth.repository;

import com.lims.auth.entity.AdminSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface AdminSessionRepository extends JpaRepository<AdminSession, String> {

    Optional<AdminSession> findByIdAndActiveTrue(String id);

    Optional<AdminSession> findByIdAndAdminUserIdAndActiveTrue(String id, String adminUserId);

    List<AdminSession> findByAdminUserIdAndActiveTrue(String adminUserId);

    List<AdminSession> findByAdminUserIdOrderByCreatedAtDesc(String adminUserId);

    List<AdminSession> findByClientIpAndActiveTrue(String clientIp);

    @Query("SELECT s FROM AdminSession s WHERE s.adminUser.id = :adminUserId AND s.active = true AND s.expiresAt > :now")
    List<AdminSession> findActiveSessionsForUser(@Param("adminUserId") String adminUserId, @Param("now") LocalDateTime now);

    @Query("SELECT s FROM AdminSession s WHERE s.expiresAt < :now AND s.active = true")
    List<AdminSession> findExpiredActiveSessions(@Param("now") LocalDateTime now);

    @Query("SELECT s FROM AdminSession s WHERE s.lastActivity < :threshold AND s.active = true")
    List<AdminSession> findInactiveSessions(@Param("threshold") LocalDateTime threshold);

    @Modifying
    @Query("UPDATE AdminSession s SET s.active = false, s.logoutAt = :logoutTime WHERE s.id = :sessionId")
    int deactivateSession(@Param("sessionId") String sessionId, @Param("logoutTime") LocalDateTime logoutTime);

    @Modifying
    @Query("UPDATE AdminSession s SET s.active = false, s.logoutAt = :logoutTime WHERE s.adminUser.id = :adminUserId AND s.active = true")
    int deactivateAllUserSessions(@Param("adminUserId") String adminUserId, @Param("logoutTime") LocalDateTime logoutTime);

    @Modifying
    @Query("UPDATE AdminSession s SET s.active = false, s.logoutAt = :logoutTime WHERE s.expiresAt < :now AND s.active = true")
    int deactivateExpiredSessions(@Param("now") LocalDateTime now, @Param("logoutTime") LocalDateTime logoutTime);

    @Modifying
    @Query("UPDATE AdminSession s SET s.lastActivity = :now WHERE s.id = :sessionId")
    int updateLastActivity(@Param("sessionId") String sessionId, @Param("now") LocalDateTime now);

    @Query("SELECT COUNT(s) FROM AdminSession s WHERE s.active = true")
    long countActiveSessions();

    @Query("SELECT COUNT(s) FROM AdminSession s WHERE s.adminUser.id = :adminUserId AND s.active = true")
    long countActiveSessionsForUser(@Param("adminUserId") String adminUserId);

    @Query("SELECT COUNT(DISTINCT s.adminUser.id) FROM AdminSession s WHERE s.active = true")
    long countActiveUsers();

    void deleteByAdminUserIdAndActiveFalse(String adminUserId);

    void deleteByCreatedAtBefore(LocalDateTime threshold);
}