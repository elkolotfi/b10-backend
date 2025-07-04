package com.lims.auth.repository;

import com.lims.auth.entity.MfaBackupCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface MfaBackupCodeRepository extends JpaRepository<MfaBackupCode, Long> {

    List<MfaBackupCode> findByAdminUserIdAndUsedFalse(String adminUserId);

    List<MfaBackupCode> findByAdminUserIdOrderByCreatedAtDesc(String adminUserId);

    Optional<MfaBackupCode> findByAdminUserIdAndCodeAndUsedFalse(String adminUserId, String code);

    boolean existsByAdminUserIdAndCodeAndUsedFalse(String adminUserId, String code);

    @Query("SELECT COUNT(c) FROM MfaBackupCode c WHERE c.adminUser.id = :adminUserId AND c.used = false")
    long countByAdminUserIdAndUsedFalse(@Param("adminUserId") String adminUserId);

    @Query("SELECT COUNT(c) FROM MfaBackupCode c WHERE c.adminUser.id = :adminUserId AND c.used = true")
    long countByAdminUserIdAndUsedTrue(@Param("adminUserId") String adminUserId);

    @Modifying
    @Query("UPDATE MfaBackupCode c SET c.used = true, c.usedAt = :usedAt WHERE c.id = :codeId")
    int markCodeAsUsed(@Param("codeId") Long codeId, @Param("usedAt") LocalDateTime usedAt);

    @Modifying
    @Query("UPDATE MfaBackupCode c SET c.used = true, c.usedAt = :usedAt WHERE c.adminUser.id = :adminUserId AND c.code = :code AND c.used = false")
    int markCodeAsUsedByUserAndCode(@Param("adminUserId") String adminUserId, @Param("code") String code, @Param("usedAt") LocalDateTime usedAt);

    @Modifying
    @Query("DELETE FROM MfaBackupCode c WHERE c.adminUser.id = :adminUserId")
    int deleteByAdminUserId(@Param("adminUserId") String adminUserId);

    @Modifying
    @Query("DELETE FROM MfaBackupCode c WHERE c.adminUser.id = :adminUserId AND c.used = true")
    int deleteUsedCodesByAdminUserId(@Param("adminUserId") String adminUserId);

    @Query("SELECT c FROM MfaBackupCode c WHERE c.usedAt < :threshold AND c.used = true")
    List<MfaBackupCode> findOldUsedCodes(@Param("threshold") LocalDateTime threshold);

    void deleteByCreatedAtBeforeAndUsedTrue(LocalDateTime threshold);
}
