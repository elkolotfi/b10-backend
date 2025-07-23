package com.lims.referential.mapper;

import com.lims.referential.entity.PatientSpecificity;
import com.lims.referential.dto.request.PatientSpecificityRequestDTO;
import com.lims.referential.dto.response.PatientSpecificityResponseDTO;
import org.mapstruct.*;

/**
 * Mapper pour la conversion entre entités PatientSpecificity et DTOs
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE,
        uses = {SpecificityCategoryMapper.class})
public interface PatientSpecificityMapper {

    /**
     * Convertit une entité PatientSpecificity en DTO de réponse
     */
    PatientSpecificityResponseDTO toResponseDTO(PatientSpecificity patientSpecificity);

    /**
     * Convertit un DTO de requête en entité PatientSpecificity
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    @Mapping(target = "category", ignore = true)
    PatientSpecificity toEntity(PatientSpecificityRequestDTO requestDTO);

    /**
     * Met à jour une entité existante avec les données du DTO
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    @Mapping(target = "category", ignore = true)
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntityFromDTO(PatientSpecificityRequestDTO requestDTO, @MappingTarget PatientSpecificity patientSpecificity);
}