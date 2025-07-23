package com.lims.referential.entity;

import com.lims.referential.entity.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.Where;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.util.List;

@Entity
@Table(name = "geographique", schema = "lims_referential")
@Where(clause = "deleted_at IS NULL")
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class Geographique extends BaseEntity {

    @Column(name = "code_postal", nullable = false, length = 10)
    @NotBlank(message = "Le code postal est obligatoire")
    @Size(max = 10)
    private String codePostal;

    @Column(name = "nom_commune", nullable = false)
    @NotBlank(message = "Le nom de la commune est obligatoire")
    @Size(max = 255)
    private String nomCommune;

    @Column(name = "code_commune", length = 10)
    @Size(max = 10)
    private String codeCommune;

    // Hiérarchie administrative
    @Column(name = "departement", nullable = false, length = 100)
    @NotBlank(message = "Le département est obligatoire")
    @Size(max = 100)
    private String departement;

    @Column(name = "code_departement", nullable = false, length = 3)
    @NotBlank(message = "Le code département est obligatoire")
    @Size(max = 3)
    private String codeDepartement;

    @Column(name = "region", nullable = false, length = 100)
    @NotBlank(message = "La région est obligatoire")
    @Size(max = 100)
    private String region;

    @Column(name = "code_region", nullable = false, length = 3)
    @NotBlank(message = "Le code région est obligatoire")
    @Size(max = 3)
    private String codeRegion;

    // Géolocalisation
    @Column(name = "latitude", precision = 10, scale = 8)
    private BigDecimal latitude;

    @Column(name = "longitude", precision = 11, scale = 8)
    private BigDecimal longitude;

    // Informations démographiques
    @Column(name = "population")
    private Integer population;

    @Column(name = "superficie_km2", precision = 8, scale = 2)
    private BigDecimal superficieKm2;

    @Column(name = "densite_hab_km2", precision = 8, scale = 2)
    private BigDecimal densiteHabKm2;

    // Zone de desserte laboratoires
    @Column(name = "laboratoires_zone", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> laboratoiresZone; // Array des IDs laboratoires

    @Column(name = "distance_laboratoire_plus_proche_km", precision = 6, scale = 2)
    private BigDecimal distanceLaboratoirePlusProcheKm;

    @Builder.Default
    @Column(name = "actif", nullable = false)
    private Boolean actif = true;
}