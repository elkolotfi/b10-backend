package com.lims.referential.mapper;

import com.lims.referential.entity.Geographique;
import com.lims.referential.dto.request.GeographiqueRequestDTO;
import com.lims.referential.dto.response.GeographiqueResponseDTO;
import org.mapstruct.*;

/**
 * Mapper pour la conversion entre entités Geographique et DTOs
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface GeographiqueMapper {

    /**
     * Convertit une entité Geographique en DTO de réponse
     */
    GeographiqueResponseDTO toResponseDTO(Geographique geographique);

    /**
     * Convertit un DTO de requête en entité Geographique
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    Geographique toEntity(GeographiqueRequestDTO requestDTO);

    /**
     * Met à jour une entité existante avec les données du DTO
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntityFromDTO(GeographiqueRequestDTO requestDTO, @MappingTarget Geographique geographique);
}