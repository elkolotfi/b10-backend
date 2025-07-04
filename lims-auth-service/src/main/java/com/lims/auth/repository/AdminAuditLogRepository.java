package com.lims.auth.repository;

import com.lims.auth.entity.AdminAuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AdminAuditLogRepository extends JpaRepository<AdminAuditLog, Long> {

    List<AdminAuditLog> findByAdminUserIdOrderByCreatedAtDesc(String adminUserId);

    Page<AdminAuditLog> findByAdminUserIdOrderByCreatedAtDesc(String adminUserId, Pageable pageable);

    List<AdminAuditLog> findByActionOrderByCreatedAtDesc(String action);

    Page<AdminAuditLog> findByActionOrderByCreatedAtDesc(String action, Pageable pageable);

    List<AdminAuditLog> findByResultOrderByCreatedAtDesc(AdminAuditLog.AuditResult result);

    Page<AdminAuditLog> findByResultOrderByCreatedAtDesc(AdminAuditLog.AuditResult result, Pageable pageable);

    List<AdminAuditLog> findByClientIpOrderByCreatedAtDesc(String clientIp);

    Page<AdminAuditLog> findByClientIpOrderByCreatedAtDesc(String clientIp, Pageable pageable);

    List<AdminAuditLog> findBySessionIdOrderByCreatedAtDesc(String sessionId);

    @Query("SELECT l FROM AdminAuditLog l WHERE l.createdAt BETWEEN :startDate AND :endDate ORDER BY l.createdAt DESC")
    List<AdminAuditLog> findByDateRange(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    @Query("SELECT l FROM AdminAuditLog l WHERE l.createdAt BETWEEN :startDate AND :endDate ORDER BY l.createdAt DESC")
    Page<AdminAuditLog> findByDateRange(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate, Pageable pageable);

    @Query("SELECT l FROM AdminAuditLog l WHERE l.adminUser.id = :adminUserId AND l.createdAt BETWEEN :startDate AND :endDate ORDER BY l.createdAt DESC")
    List<AdminAuditLog> findByAdminUserAndDateRange(@Param("adminUserId") String adminUserId, @Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    @Query("SELECT l FROM AdminAuditLog l WHERE l.action = :action AND l.result = :result ORDER BY l.createdAt DESC")
    List<AdminAuditLog> findByActionAndResult(@Param("action") String action, @Param("result") AdminAuditLog.AuditResult result);

    @Query("SELECT l FROM AdminAuditLog l WHERE l.result = 'FAILURE' AND l.createdAt > :threshold ORDER BY l.createdAt DESC")
    List<AdminAuditLog> findRecentFailures(@Param("threshold") LocalDateTime threshold);

    @Query("SELECT l FROM AdminAuditLog l WHERE l.clientIp = :clientIp AND l.result = 'FAILURE' AND l.createdAt > :threshold")
    List<AdminAuditLog> findRecentFailuresByIp(@Param("clientIp") String clientIp, @Param("threshold") LocalDateTime threshold);

    @Query("SELECT COUNT(l) FROM AdminAuditLog l WHERE l.result = 'FAILURE' AND l.createdAt > :threshold")
    long countRecentFailures(@Param("threshold") LocalDateTime threshold);

    @Query("SELECT COUNT(l) FROM AdminAuditLog l WHERE l.adminUser.id = :adminUserId AND l.result = 'FAILURE' AND l.createdAt > :threshold")
    long countRecentFailuresByUser(@Param("adminUserId") String adminUserId, @Param("threshold") LocalDateTime threshold);

    @Query("SELECT COUNT(l) FROM AdminAuditLog l WHERE l.clientIp = :clientIp AND l.result = 'FAILURE' AND l.createdAt > :threshold")
    long countRecentFailuresByIp(@Param("clientIp") String clientIp, @Param("threshold") LocalDateTime threshold);

    @Query("SELECT l.clientIp, COUNT(l) FROM AdminAuditLog l WHERE l.result = 'FAILURE' AND l.createdAt > :threshold GROUP BY l.clientIp ORDER BY COUNT(l) DESC")
    List<Object[]> findTopFailureIps(@Param("threshold") LocalDateTime threshold);

    @Query("SELECT l.action, COUNT(l) FROM AdminAuditLog l WHERE l.createdAt > :threshold GROUP BY l.action ORDER BY COUNT(l) DESC")
    List<Object[]> findTopActions(@Param("threshold") LocalDateTime threshold);

    void deleteByCreatedAtBefore(LocalDateTime threshold);
}