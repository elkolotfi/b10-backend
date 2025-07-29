package com.lims.document.mapper;

import com.lims.document.dto.DocumentDTO;
import com.lims.document.entity.Document;
import org.mapstruct.*;

@Mapper(componentModel = "spring")
public interface DocumentMapper {

    @Mapping(target = "downloadUrl", ignore = true)
    DocumentDTO toDTO(Document document);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "filename", ignore = true)
    @Mapping(target = "bucketName", ignore = true)
    @Mapping(target = "objectKey", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "status", constant = "ACTIVE")
    Document toEntity(DocumentDTO documentDTO);
}