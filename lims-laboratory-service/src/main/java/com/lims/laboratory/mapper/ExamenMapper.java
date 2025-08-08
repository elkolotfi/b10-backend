package com.lims.laboratory.mapper;

import com.lims.laboratory.dto.request.ExamenRequestDTO;
import com.lims.laboratory.dto.response.ExamenResponseDTO;
import com.lims.laboratory.entity.Examen;
import org.mapstruct.*;

@Mapper(componentModel = "spring")
public interface ExamenMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "laboratoire", ignore = true)
    @Mapping(target = "analyses", ignore = true)
    @Mapping(target = "prelevements", ignore = true)
    @Mapping(target = "tarifs", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    Examen toEntity(ExamenRequestDTO requestDTO);

    @Mapping(source = "laboratoire.id", target = "laboratoireId")
    @Mapping(source = "laboratoire.nomCommercial", target = "laboratoireNom")
    @Mapping(source = "analyses", target = "nombreAnalyses", qualifiedByName = "countAnalyses")
    @Mapping(source = "prelevements", target = "nombrePrelevements", qualifiedByName = "countPrelevements")
    @Mapping(source = "tarifs", target = "nombreTarifs", qualifiedByName = "countTarifs")
    ExamenResponseDTO toResponseDTO(Examen examen);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "laboratoire", ignore = true)
    @Mapping(target = "analyses", ignore = true)
    @Mapping(target = "prelevements", ignore = true)
    @Mapping(target = "tarifs", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    void updateEntity(ExamenRequestDTO requestDTO, @MappingTarget Examen examen);

    @Named("countAnalyses")
    default Integer countAnalyses(java.util.List<?> analyses) {
        return analyses != null ? analyses.size() : 0;
    }

    @Named("countPrelevements")
    default Integer countPrelevements(java.util.List<?> prelevements) {
        return prelevements != null ? prelevements.size() : 0;
    }

    @Named("countTarifs")
    default Integer countTarifs(java.util.List<?> tarifs) {
        return tarifs != null ? tarifs.size() : 0;
    }
}