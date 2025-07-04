package com.lims.auth.repository;

import com.lims.auth.entity.MfaSecret;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface MfaSecretRepository extends JpaRepository<MfaSecret, Long> {

    Optional<MfaSecret> findByAdminUserIdAndActiveTrue(String adminUserId);

    List<MfaSecret> findByAdminUserIdOrderByCreatedAtDesc(String adminUserId);

    boolean existsByAdminUserIdAndActiveTrue(String adminUserId);

    @Query("SELECT s FROM MfaSecret s WHERE s.adminUser.id = :adminUserId AND s.active = true")
    Optional<MfaSecret> findActiveSecretForUser(@Param("adminUserId") String adminUserId);

    @Modifying
    @Query("UPDATE MfaSecret s SET s.active = false, s.disabledAt = :disabledAt WHERE s.adminUser.id = :adminUserId AND s.active = true")
    int deactivateUserSecrets(@Param("adminUserId") String adminUserId, @Param("disabledAt") LocalDateTime disabledAt);

    @Modifying
    @Query("UPDATE MfaSecret s SET s.active = false, s.disabledAt = :disabledAt WHERE s.id = :secretId")
    int deactivateSecret(@Param("secretId") Long secretId, @Param("disabledAt") LocalDateTime disabledAt);

    @Query("SELECT COUNT(s) FROM MfaSecret s WHERE s.active = true")
    long countActiveSecrets();

    @Query("SELECT COUNT(DISTINCT s.adminUser.id) FROM MfaSecret s WHERE s.active = true")
    long countUsersWithMfa();

    void deleteByAdminUserIdAndActiveFalse(String adminUserId);

    void deleteByCreatedAtBeforeAndActiveFalse(LocalDateTime threshold);
}
