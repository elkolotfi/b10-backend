package com.lims.document.service;

import com.lims.document.dto.DocumentDTO;
import com.lims.document.dto.UploadRequestDTO;
import com.lims.document.entity.Document;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.UUID;

public interface DocumentService {

    DocumentDTO uploadDocument(MultipartFile file, UploadRequestDTO request, UUID uploadedBy);

    DocumentDTO getDocumentById(UUID id);

    byte[] downloadDocument(UUID id);

    String generateDownloadUrl(UUID id, int expirationMinutes);

    void softDeleteDocument(UUID id, UUID deletedBy);

    Page<DocumentDTO> getDocumentsByUser(UUID userId, Pageable pageable);

    List<DocumentDTO> getDocumentsByPatient(UUID patientId);

    List<DocumentDTO> getDocumentsByType(Document.DocumentType type);
}