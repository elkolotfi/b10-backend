package com.lims.referential.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;
import java.util.List;

@Data
@Builder
public class MedecinRequestDTO {

    @NotBlank(message = "Le numéro RPPS est obligatoire")
    @Pattern(regexp = "\\d{11}", message = "Le numéro RPPS doit contenir exactement 11 chiffres")
    private String numeroRpps;

    @NotBlank(message = "Le nom est obligatoire")
    @Size(max = 100, message = "Le nom ne peut pas dépasser 100 caractères")
    private String nom;

    @NotBlank(message = "Le prénom est obligatoire")
    @Size(max = 100, message = "Le prénom ne peut pas dépasser 100 caractères")
    private String prenom;

    @Size(max = 20, message = "Le titre ne peut pas dépasser 20 caractères")
    private String titre;

    @Size(max = 100, message = "La spécialité ne peut pas dépasser 100 caractères")
    private String specialitePrincipale;

    private List<String> specialitesSecondaires;

    // Adresse professionnelle
    @Valid
    private AdresseRequestDTO adresse;

    // Contact professionnel
    @Valid
    private ContactRequestDTO contact;

    @Size(max = 50, message = "Le mode d'exercice ne peut pas dépasser 50 caractères")
    private String modeExercice; // liberal, salarie, mixte

    private Integer secteurConventionnel; // 1, 2, 3

    private LocalDate dateInstallation;

    private Boolean actif = true;

    @Data
    @Builder
    public static class AdresseRequestDTO {
        @Size(max = 255)
        private String ligne1;

        @Size(max = 255)
        private String ligne2;

        @Pattern(regexp = "\\d{5}", message = "Le code postal doit contenir 5 chiffres")
        @Size(max = 10)
        private String codePostal;

        @Size(max = 100)
        private String ville;

        @Size(max = 100)
        private String departement;

        @Size(max = 100)
        private String region;

        @Builder.Default
        @Size(max = 50)
        private String pays = "France";
    }

    @Data
    @Builder
    public static class ContactRequestDTO {
        @Pattern(regexp = "^[0-9+\\-\\s()]{8,20}$", message = "Format de téléphone invalide")
        private String telephone;

        @Pattern(regexp = "^[0-9+\\-\\s()]{8,20}$", message = "Format de fax invalide")
        private String fax;

        @Email(message = "Format d'email invalide")
        @Size(max = 255)
        private String email;
    }
}