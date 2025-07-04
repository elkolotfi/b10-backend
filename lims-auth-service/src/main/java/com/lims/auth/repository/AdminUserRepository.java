// AdminUserRepository.java
package com.lims.auth.repository;

import com.lims.auth.entity.AdminUser;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface AdminUserRepository extends JpaRepository<AdminUser, String> {

    Optional<AdminUser> findByEmailIgnoreCase(String email);

    Optional<AdminUser> findByKeycloakId(String keycloakId);

    boolean existsByEmailIgnoreCase(String email);

    boolean existsByKeycloakId(String keycloakId);

    List<AdminUser> findByEnabledTrue();

    List<AdminUser> findByEnabledFalse();

    List<AdminUser> findByStatus(AdminUser.AdminStatus status);

    List<AdminUser> findByRole(AdminUser.AdminRole role);

    Page<AdminUser> findByEnabledTrue(Pageable pageable);

    Page<AdminUser> findByStatus(AdminUser.AdminStatus status, Pageable pageable);

    Page<AdminUser> findByRole(AdminUser.AdminRole role, Pageable pageable);

    @Query("SELECT u FROM AdminUser u WHERE u.enabled = true AND u.lockedUntil IS NULL")
    List<AdminUser> findActiveUsers();

    @Query("SELECT u FROM AdminUser u WHERE u.lockedUntil IS NOT NULL AND u.lockedUntil > :now")
    List<AdminUser> findLockedUsers(@Param("now") LocalDateTime now);

    @Query("SELECT u FROM AdminUser u WHERE u.failedAttempts >= :maxAttempts")
    List<AdminUser> findUsersWithFailedAttempts(@Param("maxAttempts") int maxAttempts);

    @Query("SELECT u FROM AdminUser u WHERE u.lastLogin < :threshold")
    List<AdminUser> findInactiveUsers(@Param("threshold") LocalDateTime threshold);

    @Query("SELECT u FROM AdminUser u WHERE u.mfaEnabled = false")
    List<AdminUser> findUsersWithoutMfa();

    @Query("SELECT u FROM AdminUser u WHERE u.email LIKE %:search% OR u.firstName LIKE %:search% OR u.lastName LIKE %:search%")
    Page<AdminUser> findBySearchTerm(@Param("search") String search, Pageable pageable);

    @Modifying
    @Query("UPDATE AdminUser u SET u.failedAttempts = 0, u.lockedUntil = NULL WHERE u.id = :userId")
    int resetFailedAttempts(@Param("userId") String userId);

    @Modifying
    @Query("UPDATE AdminUser u SET u.lockedUntil = :lockUntil WHERE u.id = :userId")
    int lockUser(@Param("userId") String userId, @Param("lockUntil") LocalDateTime lockUntil);

    @Modifying
    @Query("UPDATE AdminUser u SET u.enabled = false WHERE u.id = :userId")
    int disableUser(@Param("userId") String userId);

    @Modifying
    @Query("UPDATE AdminUser u SET u.enabled = true WHERE u.id = :userId")
    int enableUser(@Param("userId") String userId);

    @Query("SELECT COUNT(u) FROM AdminUser u WHERE u.enabled = true")
    long countActiveUsers();

    @Query("SELECT COUNT(u) FROM AdminUser u WHERE u.role = :role")
    long countByRole(@Param("role") AdminUser.AdminRole role);

    @Query("SELECT COUNT(u) FROM AdminUser u WHERE u.mfaEnabled = true")
    long countUsersWithMfa();
}