package com.lims.document.service.impl;

import com.lims.document.dto.DocumentDTO;
import com.lims.document.dto.UploadRequestDTO;
import com.lims.document.entity.Document;
import com.lims.document.exception.DocumentNotFoundException;
import com.lims.document.exception.DocumentUploadException;
import com.lims.document.mapper.DocumentMapper;
import com.lims.document.repository.DocumentRepository;
import com.lims.document.service.DocumentService;
import com.lims.document.service.MinioService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.tika.Tika;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class DocumentServiceImpl implements DocumentService {

    private final DocumentRepository documentRepository;
    private final MinioService minioService;
    private final DocumentMapper documentMapper;
    private final Tika tika = new Tika();

    @Override
    @Transactional
    public DocumentDTO uploadDocument(MultipartFile file, UploadRequestDTO request, UUID uploadedBy) {
        try {
            // Validation du fichier
            validateFile(file);

            // Génération d'un nom unique
            String objectKey = generateObjectKey(file.getOriginalFilename());

            // Détermination du bucket selon le type de document
            String bucketName = determineBucket(request.getDocumentType());

            // Détection du type MIME réel
            String detectedContentType = tika.detect(file.getInputStream());

            // Upload vers MinIO
            minioService.uploadFile(bucketName, objectKey, file.getInputStream(),
                    file.getSize(), detectedContentType);

            // Création de l'entité Document
            Document document = new Document();
            document.setFilename(objectKey);
            document.setOriginalFilename(file.getOriginalFilename());
            document.setContentType(detectedContentType);
            document.setFileSize(file.getSize());
            document.setBucketName(bucketName);
            document.setObjectKey(objectKey);
            document.setDocumentType(request.getDocumentType());
            document.setUploadedBy(uploadedBy);
            document.setPatientId(request.getPatientId());
            document.setRelatedEntityType(request.getRelatedEntityType());
            document.setRelatedEntityId(request.getRelatedEntityId());
            document.setDescription(request.getDescription());
            document.setTags(request.getTags());

            Document savedDocument = documentRepository.save(document);

            log.info("Document uploadé avec succès: {} par utilisateur: {}",
                    objectKey, uploadedBy);

            return documentMapper.toDTO(savedDocument);

        } catch (Exception e) {
            log.error("Erreur lors de l'upload du document: {}", e.getMessage(), e);
            throw new DocumentUploadException("Impossible d'uploader le document: " + e.getMessage(), e);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public DocumentDTO getDocumentById(UUID id) {
        Document document = documentRepository.findActiveById(id)
                .orElseThrow(() -> new DocumentNotFoundException("Document non trouvé avec l'ID: " + id));

        DocumentDTO dto = documentMapper.toDTO(document);
        dto.setDownloadUrl(generateDownloadUrl(id, 60)); // URL valide 1h

        return dto;
    }

    @Override
    public byte[] downloadDocument(UUID id) {
        Document document = documentRepository.findActiveById(id)
                .orElseThrow(() -> new DocumentNotFoundException("Document non trouvé avec l'ID: " + id));

        try {
            return minioService.downloadFile(document.getBucketName(), document.getObjectKey());
        } catch (Exception e) {
            log.error("Erreur lors du téléchargement du document {}: {}", id, e.getMessage(), e);
            throw new DocumentUploadException("Impossible de télécharger le document", e);
        }
    }

    @Override
    public String generateDownloadUrl(UUID id, int expirationMinutes) {
        Document document = documentRepository.findActiveById(id)
                .orElseThrow(() -> new DocumentNotFoundException("Document non trouvé avec l'ID: " + id));

        try {
            return minioService.generatePresignedUrl(document.getBucketName(),
                    document.getObjectKey(), expirationMinutes);
        } catch (Exception e) {
            log.error("Erreur lors de la génération de l'URL de téléchargement pour {}: {}",
                    id, e.getMessage(), e);
            throw new DocumentUploadException("Impossible de générer l'URL de téléchargement", e);
        }
    }

    @Override
    @Transactional
    public void softDeleteDocument(UUID id, UUID deletedBy) {
        Document document = documentRepository.findActiveById(id)
                .orElseThrow(() -> new DocumentNotFoundException("Document non trouvé avec l'ID: " + id));

        document.setStatus(Document.DocumentStatus.DELETED);
        document.setDeletedAt(LocalDateTime.now());

        documentRepository.save(document);

        log.info("Document {} supprimé (soft delete) par utilisateur: {}", id, deletedBy);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<DocumentDTO> getDocumentsByUser(UUID userId, Pageable pageable) {
        return documentRepository.findActiveByUploadedBy(userId, pageable)
                .map(documentMapper::toDTO);
    }

    @Override
    @Transactional(readOnly = true)
    public List<DocumentDTO> getDocumentsByPatient(UUID patientId) {
        return documentRepository.findActiveByPatientId(patientId)
                .stream()
                .map(documentMapper::toDTO)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public List<DocumentDTO> getDocumentsByType(Document.DocumentType type) {
        return documentRepository.findActiveByDocumentType(type)
                .stream()
                .map(documentMapper::toDTO)
                .toList();
    }

    // Méthodes privées
    private void validateFile(MultipartFile file) {
        if (file.isEmpty()) {
            throw new DocumentUploadException("Le fichier ne peut pas être vide");
        }

        // Validation de la taille (max 50MB)
        if (file.getSize() > 50 * 1024 * 1024) {
            throw new DocumentUploadException("Le fichier ne peut pas dépasser 50MB");
        }

        // Validation des types de fichier autorisés
        String contentType = file.getContentType();
        if (contentType == null || !isAllowedContentType(contentType)) {
            throw new DocumentUploadException("Type de fichier non autorisé: " + contentType);
        }
    }

    private boolean isAllowedContentType(String contentType) {
        return contentType.equals("application/pdf") ||
                contentType.equals("image/jpeg") ||
                contentType.equals("image/png") ||
                contentType.equals("image/gif") ||
                contentType.equals("image/webp");
    }

    private String generateObjectKey(String originalFilename) {
        String extension = getFileExtension(originalFilename);
        return UUID.randomUUID().toString() + (extension.isEmpty() ? "" : "." + extension);
    }

    private String getFileExtension(String filename) {
        if (filename == null || filename.lastIndexOf(".") == -1) {
            return "";
        }
        return filename.substring(filename.lastIndexOf(".") + 1);
    }

    private String determineBucket(Document.DocumentType documentType) {
        return switch (documentType) {
            case PRESCRIPTION -> "lims-prescriptions";
            case INSURANCE_CARD -> "lims-insurance";
            case MEDICAL_RESULT -> "lims-results";
            case IDENTITY_CARD, GENERAL_DOCUMENT -> "lims-documents";
        };
    }
}