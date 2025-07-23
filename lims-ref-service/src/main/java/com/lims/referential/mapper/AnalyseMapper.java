package com.lims.referential.mapper;

import com.lims.referential.entity.Analyse;
import com.lims.referential.dto.request.AnalyseRequestDTO;
import com.lims.referential.dto.response.AnalyseResponseDTO;
import org.mapstruct.*;

/**
 * Mapper pour la conversion entre entités Analyse et DTOs
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface AnalyseMapper {

    /**
     * Convertit une entité Analyse en DTO de réponse
     */
    AnalyseResponseDTO toResponseDTO(Analyse analyse);

    /**
     * Convertit un DTO de requête en entité Analyse
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    Analyse toEntity(AnalyseRequestDTO requestDTO);

    /**
     * Met à jour une entité existante avec les données du DTO
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntityFromDTO(AnalyseRequestDTO requestDTO, @MappingTarget Analyse analyse);
}