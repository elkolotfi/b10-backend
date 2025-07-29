package com.lims.document.dto;

import com.lims.document.entity.Document;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
public class DocumentDTO {
    private UUID id;
    private String filename;
    private String originalFilename;
    private String contentType;
    private Long fileSize;
    private Document.DocumentType documentType;
    private Document.DocumentStatus status;
    private UUID uploadedBy;
    private UUID patientId;
    private String relatedEntityType;
    private UUID relatedEntityId;
    private String description;
    private String[] tags;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String downloadUrl;  // URL temporaire générée à la demande
}