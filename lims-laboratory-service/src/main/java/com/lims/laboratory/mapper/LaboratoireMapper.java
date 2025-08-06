package com.lims.laboratory.mapper;

import com.lims.laboratory.dto.request.LaboratoireRequestDTO;
import com.lims.laboratory.dto.response.LaboratoireResponseDTO;
import com.lims.laboratory.entity.Laboratoire;
import org.mapstruct.*;

import java.util.List;

/**
 * Mapper MapStruct pour les conversions entre Entity et DTO de Laboratoire
 */
@Mapper(componentModel = "spring")
public interface LaboratoireMapper {

    /**
     * Convertit une entité Laboratoire en DTO de réponse
     *
     * @param laboratoire L'entité à convertir
     * @return Le DTO de réponse
     */
    LaboratoireResponseDTO toResponseDTO(Laboratoire laboratoire);

    /**
     * Convertit une liste d'entités Laboratoire en liste de DTOs de réponse
     *
     * @param laboratoires La liste d'entités à convertir
     * @return La liste de DTOs de réponse
     */
    List<LaboratoireResponseDTO> toResponseDTOList(List<Laboratoire> laboratoires);

    /**
     * Convertit un DTO de requête en entité Laboratoire
     *
     * @param requestDTO Le DTO de requête
     * @return L'entité Laboratoire
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    Laboratoire toEntity(LaboratoireRequestDTO requestDTO);

    /**
     * Met à jour une entité Laboratoire existante avec les données du DTO de requête
     * Les champs null dans le DTO ne modifient pas l'entité existante
     *
     * @param requestDTO Le DTO contenant les nouvelles données
     * @param laboratoire L'entité existante à mettre à jour
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntity(LaboratoireRequestDTO requestDTO, @MappingTarget Laboratoire laboratoire);
}