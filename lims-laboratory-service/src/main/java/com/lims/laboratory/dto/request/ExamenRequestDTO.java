package com.lims.laboratory.dto.request;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExamenRequestDTO {

    @NotNull(message = "L'ID du laboratoire est obligatoire")
    private UUID laboratoireId;

    @NotNull(message = "L'ID de l'examen référentiel est obligatoire")
    private UUID examenReferentielId;

    @Size(max = 500, message = "Le nom de l'examen ne peut pas dépasser 500 caractères")
    private String nomExamenLabo;

    private Boolean examenActif = true;

    private Boolean examenRealiseInternement = true;

    @Size(max = 100, message = "Le délai de rendu habituel ne peut pas dépasser 100 caractères")
    private String delaiRenduHabituel;

    @Size(max = 100, message = "Le délai de rendu urgent ne peut pas dépasser 100 caractères")
    private String delaiRenduUrgent;

    @Size(max = 2000, message = "Les conditions particulières ne peuvent pas dépasser 2000 caractères")
    private String conditionsParticulieres;
}