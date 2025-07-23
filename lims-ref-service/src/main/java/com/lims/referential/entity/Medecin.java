// Medecin.java
package com.lims.referential.entity;

import com.lims.referential.enums.analyses.Civilite;
import com.lims.referential.enums.medecins.SecteurConventionnement;
import com.lims.referential.enums.medecins.SpecialiteMedicale;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.Where;
import org.hibernate.type.SqlTypes;

import java.util.List;
import java.util.Map;

/**
 * Entité représentant un médecin avec numéro RPPS
 */
@Entity
@Table(name = "medecins", schema = "lims_referential")
@Where(clause = "deleted_at IS NULL")
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class Medecin extends BaseEntity {

    @Column(name = "numero_rpps", unique = true, nullable = false, length = 11)
    @NotBlank(message = "Le numéro RPPS est obligatoire")
    @Pattern(regexp = "\\d{11}", message = "Le numéro RPPS doit contenir exactement 11 chiffres")
    private String numeroRpps;

    @Column(name = "civilite", length = 20)
    @Enumerated(EnumType.STRING)
    private Civilite civilite;

    @Column(name = "nom", nullable = false, length = 100)
    @NotBlank(message = "Le nom est obligatoire")
    @Size(max = 100, message = "Le nom ne peut pas dépasser 100 caractères")
    private String nom;

    @Column(name = "prenom", nullable = false, length = 100)
    @NotBlank(message = "Le prénom est obligatoire")
    @Size(max = 100, message = "Le prénom ne peut pas dépasser 100 caractères")
    private String prenom;

    @Column(name = "specialite_principale", length = 100)
    @Enumerated(EnumType.STRING)
    private SpecialiteMedicale specialitePrincipale;

    @Column(name = "specialites_secondaires", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<SpecialiteMedicale> specialitesSecondaires;

    // Adresse professionnelle
    @Embedded
    @AttributeOverrides({
            @AttributeOverride(name = "ligne1", column = @Column(name = "adresse_ligne1")),
            @AttributeOverride(name = "ligne2", column = @Column(name = "adresse_ligne2")),
            @AttributeOverride(name = "codePostal", column = @Column(name = "code_postal")),
            @AttributeOverride(name = "ville", column = @Column(name = "ville")),
            @AttributeOverride(name = "departement", column = @Column(name = "departement")),
            @AttributeOverride(name = "region", column = @Column(name = "region")),
            @AttributeOverride(name = "pays", column = @Column(name = "pays"))
    })
    private Adresse adresse;

    // Contact professionnel
    @Embedded
    @AttributeOverrides({
            @AttributeOverride(name = "telephone", column = @Column(name = "telephone")),
            @AttributeOverride(name = "fax", column = @Column(name = "fax")),
            @AttributeOverride(name = "email", column = @Column(name = "email"))
    })
    private Contact contact;

    @Column(name = "secteur_conventionnement")
    @Enumerated(EnumType.STRING)
    private SecteurConventionnement secteurConventionnement;

    @Builder.Default
    @Column(name = "conventionne_secu")
    private Boolean conventionneSecu = true;

    @Builder.Default
    @Column(name = "carte_vitale")
    private Boolean cartevitale = true;

    @Builder.Default
    @Column(name = "rdv_en_ligne")
    private Boolean rdvEnLigne = false;

    @Column(name = "horaires_consultation", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, List<String>> horairesConsultation;

    @Column(name = "observations_speciales", columnDefinition = "TEXT")
    private String observationsSpeciales;

    @Builder.Default
    @Column(name = "actif", nullable = false)
    private Boolean actif = true;

    // Classes internes
    @Embeddable
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Adresse {
        @Size(max = 255)
        private String ligne1;

        @Size(max = 255)
        private String ligne2;

        @Size(max = 10)
        @Pattern(regexp = "\\d{5}", message = "Le code postal doit contenir 5 chiffres")
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

    @Embeddable
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Contact {
        @Pattern(regexp = "^[0-9+\\-\\s()]{8,20}$", message = "Format de téléphone invalide")
        private String telephone;

        @Pattern(regexp = "^[0-9+\\-\\s()]{8,20}$", message = "Format de fax invalide")
        private String fax;

        @Email(message = "Format d'email invalide")
        @Size(max = 255)
        private String email;
    }
}