package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class MedecinResponseDTO {

    private UUID id;
    private String numeroRpps;
    private String nom;
    private String prenom;
    private String titre;
    private String specialitePrincipale;
    private List<String> specialitesSecondaires;

    // Adresse professionnelle
    private AdresseResponseDTO adresse;

    // Contact professionnel
    private ContactResponseDTO contact;

    private String modeExercice;
    private Integer secteurConventionnel;
    private LocalDate dateInstallation;
    private Boolean actif;

    // Métadonnées
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Integer version;

    @Data
    @Builder
    public static class AdresseResponseDTO {
        private String ligne1;
        private String ligne2;
        private String codePostal;
        private String ville;
        private String departement;
        private String region;
        private String pays;
    }

    @Data
    @Builder
    public static class ContactResponseDTO {
        private String telephone;
        private String fax;
        private String email;
    }
}