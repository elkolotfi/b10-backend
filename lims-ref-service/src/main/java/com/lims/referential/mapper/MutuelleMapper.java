package com.lims.referential.mapper;

import com.lims.referential.entity.Mutuelle;
import com.lims.referential.dto.request.MutuelleRequestDTO;
import com.lims.referential.dto.response.MutuelleResponseDTO;
import org.mapstruct.*;

/**
 * Mapper pour la conversion entre entités Mutuelle et DTOs
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface MutuelleMapper {

    /**
     * Convertit une entité Mutuelle en DTO de réponse
     */
    @Mapping(target = "adresse", source = ".")
    @Mapping(target = "contact", source = ".")
    @Mapping(target = "priseEnCharge", source = ".")
    @Mapping(target = "facturation", source = ".")
    MutuelleResponseDTO toResponseDTO(Mutuelle mutuelle);

    /**
     * Convertit un DTO de requête en entité Mutuelle
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    @Mapping(target = "adresseLigne1", source = "adresse.ligne1")
    @Mapping(target = "adresseLigne2", source = "adresse.ligne2")
    @Mapping(target = "codePostal", source = "adresse.codePostal")
    @Mapping(target = "ville", source = "adresse.ville")
    @Mapping(target = "departement", source = "adresse.departement")
    @Mapping(target = "region", source = "adresse.region")
    @Mapping(target = "telephone", source = "contact.telephone")
    @Mapping(target = "fax", source = "contact.fax")
    @Mapping(target = "email", source = "contact.email")
    @Mapping(target = "siteWeb", source = "contact.siteWeb")
    @Mapping(target = "tauxBaseRemboursement", source = "priseEnCharge.tauxBaseRemboursement")
    @Mapping(target = "plafondAnnuelEuro", source = "priseEnCharge.plafondAnnuelEuro")
    @Mapping(target = "franchiseEuro", source = "priseEnCharge.franchiseEuro")
    @Mapping(target = "analysesCouvertes", source = "priseEnCharge.analysesCouvertes")
    @Mapping(target = "analysesExclues", source = "priseEnCharge.analysesExclues")
    @Mapping(target = "codesFacturation", source = "facturation.codesFacturation")
    @Mapping(target = "delaiPaiementJours", source = "facturation.delaiPaiementJours")
    @Mapping(target = "modeTransmission", source = "facturation.modeTransmission")
    Mutuelle toEntity(MutuelleRequestDTO requestDTO);

    /**
     * Met à jour une entité existante avec les données du DTO
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    @Mapping(target = "adresseLigne1", source = "adresse.ligne1")
    @Mapping(target = "adresseLigne2", source = "adresse.ligne2")
    @Mapping(target = "codePostal", source = "adresse.codePostal")
    @Mapping(target = "ville", source = "adresse.ville")
    @Mapping(target = "departement", source = "adresse.departement")
    @Mapping(target = "region", source = "adresse.region")
    @Mapping(target = "telephone", source = "contact.telephone")
    @Mapping(target = "fax", source = "contact.fax")
    @Mapping(target = "email", source = "contact.email")
    @Mapping(target = "siteWeb", source = "contact.siteWeb")
    @Mapping(target = "tauxBaseRemboursement", source = "priseEnCharge.tauxBaseRemboursement")
    @Mapping(target = "plafondAnnuelEuro", source = "priseEnCharge.plafondAnnuelEuro")
    @Mapping(target = "franchiseEuro", source = "priseEnCharge.franchiseEuro")
    @Mapping(target = "analysesCouvertes", source = "priseEnCharge.analysesCouvertes")
    @Mapping(target = "analysesExclues", source = "priseEnCharge.analysesExclues")
    @Mapping(target = "codesFacturation", source = "facturation.codesFacturation")
    @Mapping(target = "delaiPaiementJours", source = "facturation.delaiPaiementJours")
    @Mapping(target = "modeTransmission", source = "facturation.modeTransmission")
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntityFromDTO(MutuelleRequestDTO requestDTO, @MappingTarget Mutuelle mutuelle);

    // Méthodes de mapping pour les sous-objets
    @Mapping(target = "ligne1", source = "adresseLigne1")
    @Mapping(target = "ligne2", source = "adresseLigne2")
    @Mapping(target = "codePostal", source = "codePostal")
    @Mapping(target = "ville", source = "ville")
    @Mapping(target = "departement", source = "departement")
    @Mapping(target = "region", source = "region")
    MutuelleResponseDTO.AdresseMutuelleResponseDTO toAdresseResponseDTO(Mutuelle mutuelle);

    @Mapping(target = "telephone", source = "telephone")
    @Mapping(target = "fax", source = "fax")
    @Mapping(target = "email", source = "email")
    @Mapping(target = "siteWeb", source = "siteWeb")
    MutuelleResponseDTO.ContactMutuelleResponseDTO toContactResponseDTO(Mutuelle mutuelle);

    @Mapping(target = "tauxBaseRemboursement", source = "tauxBaseRemboursement")
    @Mapping(target = "plafondAnnuelEuro", source = "plafondAnnuelEuro")
    @Mapping(target = "franchiseEuro", source = "franchiseEuro")
    @Mapping(target = "analysesCouvertes", source = "analysesCouvertes")
    @Mapping(target = "analysesExclues", source = "analysesExclues")
    MutuelleResponseDTO.PriseEnChargeResponseDTO toPriseEnChargeResponseDTO(Mutuelle mutuelle);

    @Mapping(target = "codesFacturation", source = "codesFacturation")
    @Mapping(target = "delaiPaiementJours", source = "delaiPaiementJours")
    @Mapping(target = "modeTransmission", source = "modeTransmission")
    MutuelleResponseDTO.FacturationResponseDTO toFacturationResponseDTO(Mutuelle mutuelle);

    // Mapping des analyses couvertes
    MutuelleResponseDTO.AnalyseCouvertureResponseDTO toAnalyseCouvertureResponseDTO(Mutuelle.AnalyseCouverture analyseCouverture);
    Mutuelle.AnalyseCouverture toAnalyseCouvertureEntity(MutuelleRequestDTO.AnalyseCouvertureRequestDTO analyseCouvertureRequestDTO);
}