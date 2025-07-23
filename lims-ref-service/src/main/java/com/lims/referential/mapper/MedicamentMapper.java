package com.lims.referential.mapper;

import com.lims.referential.dto.request.CreateMedicamentRequest;
import com.lims.referential.dto.request.UpdateMedicamentRequest;
import com.lims.referential.dto.response.MedicamentResponse;
import com.lims.referential.entity.Medicament;
import org.mapstruct.*;

import java.util.List;
import java.util.UUID;

/**
 * Mapper MapStruct pour les entités Medicament.
 * Convertit entre entités JPA et DTOs REST.
 */
@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.IGNORE,
        nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE
)
public interface MedicamentMapper {

    // ============================================
    // CONVERSION ENTITY -> DTO
    // ============================================

    /**
     * Convertit une entité Medicament en MedicamentResponse
     */
    @Mapping(target = "id", source = "id", qualifiedByName = "uuidToString")
    @Mapping(target = "actif", source = "actif")
    MedicamentResponse toResponse(Medicament medicament);

    /**
     * Convertit une liste d'entités en liste de DTOs
     */
    List<MedicamentResponse> toResponseList(List<Medicament> medicaments);

    // ============================================
    // CONVERSION DTO -> ENTITY
    // ============================================

    /**
     * Convertit une demande de création en entité
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "dateCreation", ignore = true)
    @Mapping(target = "dateModification", ignore = true)
    @Mapping(target = "creePar", ignore = true)
    @Mapping(target = "modifiePar", ignore = true)
    @Mapping(target = "version", ignore = true)
    Medicament toEntity(CreateMedicamentRequest request);

    /**
     * Met à jour une entité existante avec les données de la requête
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "dateCreation", ignore = true)
    @Mapping(target = "dateModification", ignore = true)
    @Mapping(target = "creePar", ignore = true)
    @Mapping(target = "modifiePar", ignore = true)
    @Mapping(target = "version", ignore = true)
    void updateEntityFromRequest(UpdateMedicamentRequest request, @MappingTarget Medicament medicament);

    // ============================================
    // MÉTHODES UTILITAIRES
    // ============================================

    /**
     * Convertit UUID en String
     */
    @Named("uuidToString")
    default String uuidToString(UUID uuid) {
        return uuid != null ? uuid.toString() : null;
    }

    /**
     * Convertit String en UUID
     */
    @Named("stringToUuid")
    default UUID stringToUuid(String str) {
        return str != null ? UUID.fromString(str) : null;
    }
}