package com.lims.laboratory.mapper;

import com.lims.laboratory.dto.request.PrelevementRequestDTO;
import com.lims.laboratory.dto.response.PrelevementResponseDTO;
import com.lims.laboratory.entity.LaboratoirePrelevement;
import org.mapstruct.*;

import java.util.List;

/**
 * Mapper MapStruct pour les conversions entre Entity et DTO de Prelevement
 */
@Mapper(componentModel = "spring")
public interface PrelevementMapper {

    /**
     * Convertit une entité LaboratoirePrelevement en DTO de réponse
     */
    @Mapping(target = "nomLaboratoire", source = "laboratoire.nomCommercial")
    @Mapping(target = "nomExamen", source = "laboratoireExamen.nomExamenLabo")
    PrelevementResponseDTO toResponseDTO(LaboratoirePrelevement entity);

    /**
     * Convertit une liste d'entités en liste de DTOs de réponse
     */
    List<PrelevementResponseDTO> toResponseDTOList(List<LaboratoirePrelevement> entities);

    /**
     * Convertit un DTO de requête en entité
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "laboratoire", ignore = true)
    @Mapping(target = "laboratoireExamen", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    LaboratoirePrelevement toEntity(PrelevementRequestDTO requestDTO);

    /**
     * Met à jour une entité existante avec les données du DTO de requête
     * Les champs null dans le DTO ne modifient pas l'entité existante
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "laboratoireId", ignore = true)
    @Mapping(target = "laboratoireExamenId", ignore = true)
    @Mapping(target = "laboratoire", ignore = true)
    @Mapping(target = "laboratoireExamen", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntity(PrelevementRequestDTO requestDTO, @MappingTarget LaboratoirePrelevement entity);
}