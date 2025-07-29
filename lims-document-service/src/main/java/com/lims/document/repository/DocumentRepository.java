package com.lims.document.repository;

import com.lims.document.entity.Document;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface DocumentRepository extends JpaRepository<Document, UUID> {

    // Recherche des documents actifs uniquement
    @Query("SELECT d FROM Document d WHERE d.status = 'ACTIVE' AND d.deletedAt IS NULL")
    List<Document> findAllActive();

    @Query("SELECT d FROM Document d WHERE d.id = :id AND d.status = 'ACTIVE' AND d.deletedAt IS NULL")
    Optional<Document> findActiveById(@Param("id") UUID id);

    @Query("SELECT d FROM Document d WHERE d.patientId = :patientId AND d.status = 'ACTIVE' AND d.deletedAt IS NULL")
    List<Document> findActiveByPatientId(@Param("patientId") UUID patientId);

    @Query("SELECT d FROM Document d WHERE d.documentType = :type AND d.status = 'ACTIVE' AND d.deletedAt IS NULL")
    List<Document> findActiveByDocumentType(@Param("type") Document.DocumentType type);

    @Query("SELECT d FROM Document d WHERE d.uploadedBy = :userId AND d.status = 'ACTIVE' AND d.deletedAt IS NULL")
    Page<Document> findActiveByUploadedBy(@Param("userId") UUID userId, Pageable pageable);

    Optional<Document> findByObjectKeyAndStatusAndDeletedAtIsNull(String objectKey, Document.DocumentStatus status);
}