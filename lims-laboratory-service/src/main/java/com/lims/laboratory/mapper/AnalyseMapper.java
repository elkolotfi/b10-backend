package com.lims.laboratory.mapper;

import com.lims.laboratory.dto.request.AnalyseRequestDTO;
import com.lims.laboratory.dto.response.AnalyseResponseDTO;
import com.lims.laboratory.entity.LaboratoireAnalyse;
import org.mapstruct.*;

import java.util.List;

@Mapper(componentModel = "spring")
public interface AnalyseMapper {
    @Mapping(target = "nomLaboratoire", source = "laboratoire.nomCommercial")
    @Mapping(target = "nomExamen", source = "examen.nomExamenLabo")
    AnalyseResponseDTO toResponseDTO(LaboratoireAnalyse entity);

    List<AnalyseResponseDTO> toResponseDTOList(List<LaboratoireAnalyse> entities);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "laboratoire", ignore = true)
    @Mapping(target = "examen", ignore = true)
    LaboratoireAnalyse toEntity(AnalyseRequestDTO requestDTO);

    // === MISE À JOUR ENTITY ===

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "laboratoireId", ignore = true)
    @Mapping(target = "laboratoireExamenId", ignore = true)
    @Mapping(target = "analyseReferentielId", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "laboratoire", ignore = true)
    @Mapping(target = "examen", ignore = true)
    void updateEntity(@MappingTarget LaboratoireAnalyse entity, AnalyseRequestDTO requestDTO);
}