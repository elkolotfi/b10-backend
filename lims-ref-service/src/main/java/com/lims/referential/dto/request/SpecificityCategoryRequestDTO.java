package com.lims.referential.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SpecificityCategoryRequestDTO {

    @NotBlank(message = "L'ID de la catégorie est obligatoire")
    @Size(max = 50, message = "L'ID ne peut pas dépasser 50 caractères")
    private String id;

    @NotBlank(message = "Le nom est obligatoire")
    @Size(max = 255, message = "Le nom ne peut pas dépasser 255 caractères")
    private String nom;

    private String description;

    @Size(max = 7, message = "La couleur doit être un code hex valide")
    private String couleur; // Code couleur hex

    @Size(max = 50, message = "L'icône ne peut pas dépasser 50 caractères")
    private String icone;

    @Builder.Default
    private Integer ordreAffichage = 0;

    @Builder.Default
    private Boolean actif = true;
}