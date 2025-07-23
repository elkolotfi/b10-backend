package com.lims.referential.mapper;

import com.lims.referential.entity.SpecificityCategory;
import com.lims.referential.dto.request.SpecificityCategoryRequestDTO;
import com.lims.referential.dto.response.SpecificityCategoryResponseDTO;
import org.mapstruct.*;

/**
 * Mapper pour la conversion entre entités SpecificityCategory et DTOs
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface SpecificityCategoryMapper {

    /**
     * Convertit une entité SpecificityCategory en DTO de réponse
     */
    @Mapping(target = "specificities", ignore = true) // Éviter les références circulaires
    SpecificityCategoryResponseDTO toResponseDTO(SpecificityCategory specificityCategory);

    /**
     * Convertit un DTO de requête en entité SpecificityCategory
     */
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "specificities", ignore = true)
    SpecificityCategory toEntity(SpecificityCategoryRequestDTO requestDTO);

    /**
     * Met à jour une entité existante avec les données du DTO
     */
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "specificities", ignore = true)
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntityFromDTO(SpecificityCategoryRequestDTO requestDTO, @MappingTarget SpecificityCategory specificityCategory);
}