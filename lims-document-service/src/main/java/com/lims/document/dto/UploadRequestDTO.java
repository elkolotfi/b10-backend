package com.lims.document.dto;

import com.lims.document.entity.Document;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.UUID;

@Data
public class UploadRequestDTO {

    @NotNull(message = "Le type de document est obligatoire")
    private Document.DocumentType documentType;

    private UUID patientId;
    private String relatedEntityType;
    private UUID relatedEntityId;
    private String description;
    private String[] tags;
}