package com.lims.referential.mapper;

import com.lims.referential.entity.Medecin;
import com.lims.referential.dto.request.MedecinRequestDTO;
import com.lims.referential.dto.response.MedecinResponseDTO;
import org.mapstruct.*;

/**
 * Mapper pour la conversion entre entités Medecin et DTOs
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface MedecinMapper {

    MedecinResponseDTO toResponseDTO(Medecin medecin);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    Medecin toEntity(MedecinRequestDTO requestDTO);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntityFromDTO(MedecinRequestDTO requestDTO, @MappingTarget Medecin medecin);
}
