package com.lims.referential.mapper;

import com.lims.referential.dto.request.MedicamentRequestDTO;
import com.lims.referential.entity.Laboratoire;
import com.lims.referential.dto.request.LaboratoireRequestDTO;
import com.lims.referential.dto.response.LaboratoireResponseDTO;
import com.lims.referential.entity.Medicament;
import org.mapstruct.*;

/**
 * Mapper pour la conversion entre entités Laboratoire et DTOs
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface LaboratoireMapper {

    /**
     * Convertit une entité Laboratoire en DTO de réponse
     */
    @Mapping(target = "contact", source = ".")
    @Mapping(target = "informationsPratiques", source = ".")
    @Mapping(target = "capacitesTechniques", source = ".")
    LaboratoireResponseDTO toResponseDTO(Laboratoire laboratoire);

    /**
     * Convertit un DTO de requête en entité Laboratoire
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "dateCreation", ignore = true)     // ✅ Corrigé
    @Mapping(target = "dateModification", ignore = true) // ✅ Corrigé
    @Mapping(target = "creePar", ignore = true)          // ✅ Corrigé
    @Mapping(target = "modifiePar", ignore = true)       // ✅ Corrigé
    @Mapping(target = "version", ignore = true)
    @Mapping(target = "telephone", source = "contact.telephone")
    @Mapping(target = "fax", source = "contact.fax")
    @Mapping(target = "email", source = "contact.email")
    @Mapping(target = "siteWeb", source = "contact.siteWeb")
    @Mapping(target = "horairesOuverture", source = "informationsPratiques.horairesOuverture")
    @Mapping(target = "parkingDisponible", source = "informationsPratiques.parkingDisponible")
    @Mapping(target = "accesHandicapes", source = "informationsPratiques.accesHandicapes")
    @Mapping(target = "transportPublic", source = "informationsPratiques.transportPublic")
    @Mapping(target = "analysesDisponibles", source = "capacitesTechniques.analysesDisponibles")
    @Mapping(target = "specialitesTechniques", source = "capacitesTechniques.specialitesTechniques")
    @Mapping(target = "equipementsSpeciaux", source = "capacitesTechniques.equipementsSpeciaux")
    Laboratoire toEntity(LaboratoireRequestDTO requestDTO);

    /**
     * Met à jour une entité Laboratoire existante avec les données du DTO
     * ❌ ERREUR CORRIGÉE: Utilise LaboratoireRequestDTO au lieu de MedicamentRequestDTO
     * ❌ ERREUR CORRIGÉE: Target Laboratoire au lieu de Medicament
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "dateCreation", ignore = true)     // ✅ Propriétés correctes
    @Mapping(target = "dateModification", ignore = true) // ✅ selon l'entité Medicament
    @Mapping(target = "creePar", ignore = true)          // ✅ fournie
    @Mapping(target = "modifiePar", ignore = true)       // ✅
    @Mapping(target = "version", ignore = true)
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntityFromDTO(LaboratoireRequestDTO requestDTO, @MappingTarget Laboratoire laboratoire);

    // ============================================
    // MÉTHODES POUR MEDICAMENT (SI NÉCESSAIRES)
    // ============================================

    /**
     * Si vous avez besoin de mapper des médicaments aussi, ajoutez cette méthode séparée
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "dateCreation", ignore = true)
    @Mapping(target = "dateModification", ignore = true)
    @Mapping(target = "creePar", ignore = true)
    @Mapping(target = "modifiePar", ignore = true)
    @Mapping(target = "version", ignore = true)
    // Mappings spécifiques au médicament selon votre MedicamentRequestDTO
    @Mapping(target = "denomination", source = "nomCommercial")  // ✅ Mapping nom commercial -> denomination
    @Mapping(target = "codeCis", source = "codeCip")             // ✅ Si vous voulez mapper CIP -> CIS
    @Mapping(target = "formePharma", source = "formePharmaceutique")
    @Mapping(target = "voiesAdmin", source = "voieAdministration")
    @Mapping(target = "laboratoireTitulaire", source = "laboratoireFabricant")
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateMedicamentFromDTO(MedicamentRequestDTO requestDTO, @MappingTarget Medicament medicament);

    /**
     * Convertit MedicamentRequestDTO en entité Medicament
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "dateCreation", ignore = true)
    @Mapping(target = "dateModification", ignore = true)
    @Mapping(target = "creePar", ignore = true)
    @Mapping(target = "modifiePar", ignore = true)
    @Mapping(target = "version", ignore = true)
    @Mapping(target = "denomination", source = "nomCommercial")
    @Mapping(target = "codeCis", source = "codeCip")  // ⚠️ Attention: CIP ≠ CIS selon ANSM
    @Mapping(target = "formePharma", source = "formePharmaceutique")
    @Mapping(target = "voiesAdmin", source = "voieAdministration")
    @Mapping(target = "laboratoireTitulaire", source = "laboratoireFabricant")
    @Mapping(target = "statutBdm", source = "statutCommercialisation")
    Medicament medicamentRequestToEntity(MedicamentRequestDTO requestDTO);
}