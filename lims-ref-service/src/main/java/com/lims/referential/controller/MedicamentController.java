package com.lims.referential.controller;

import com.lims.referential.dto.request.CreateMedicamentRequest;
import com.lims.referential.dto.request.UpdateMedicamentRequest;
import com.lims.referential.dto.response.MedicamentResponse;
import com.lims.referential.service.MedicamentService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Contrôleur REST pour la gestion des médicaments référentiels.
 * Accessible uniquement aux administrateurs.
 */
@RestController
@RequestMapping("/api/v1/referential/medicaments")
@Tag(name = "Medicaments", description = "Gestion des médicaments référentiels")
@SecurityRequirement(name = "Bearer Authentication")
@RequiredArgsConstructor
@Slf4j
public class MedicamentController {

    private final MedicamentService medicamentService;

    // ============================================
    // ENDPOINTS DE CONSULTATION
    // ============================================

    @GetMapping
    @Operation(summary = "Liste des médicaments avec pagination",
            description = "Récupère la liste paginée de tous les médicaments")
    @ApiResponse(responseCode = "200", description = "Liste récupérée avec succès")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<MedicamentResponse>> getAllMedicaments(
            @PageableDefault(size = 20) Pageable pageable) {

        log.debug("Récupération des médicaments avec pagination: {}", pageable);
        Page<MedicamentResponse> medicaments = medicamentService.findAll(pageable);
        return ResponseEntity.ok(medicaments);
    }

    @GetMapping("/actifs")
    @Operation(summary = "Liste des médicaments actifs",
            description = "Récupère tous les médicaments actifs (non paginé)")
    @ApiResponse(responseCode = "200", description = "Liste récupérée avec succès")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<MedicamentResponse>> getMedicamentsActifs() {

        log.debug("Récupération de tous les médicaments actifs");
        List<MedicamentResponse> medicaments = medicamentService.findAllActifs();
        return ResponseEntity.ok(medicaments);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Détails d'un médicament",
            description = "Récupère les détails d'un médicament par son ID")
    @ApiResponse(responseCode = "200", description = "Médicament trouvé")
    @ApiResponse(responseCode = "404", description = "Médicament non trouvé")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<MedicamentResponse> getMedicamentById(
            @Parameter(description = "ID du médicament") @PathVariable UUID id) {

        log.debug("Récupération du médicament: {}", id);
        MedicamentResponse medicament = medicamentService.findById(id);
        return ResponseEntity.ok(medicament);
    }

    @GetMapping("/code-cis/{codeCis}")
    @Operation(summary = "Médicament par code CIS",
            description = "Récupère un médicament par son code CIS")
    @ApiResponse(responseCode = "200", description = "Médicament trouvé")
    @ApiResponse(responseCode = "404", description = "Médicament non trouvé")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<MedicamentResponse> getMedicamentByCodeCis(
            @Parameter(description = "Code CIS du médicament") @PathVariable String codeCis) {

        log.debug("Récupération du médicament avec code CIS: {}", codeCis);
        MedicamentResponse medicament = medicamentService.findByCodeCis(codeCis);
        return ResponseEntity.ok(medicament);
    }

    // ============================================
    // ENDPOINTS DE RECHERCHE
    // ============================================

    @GetMapping("/search")
    @Operation(summary = "Recherche de médicaments",
            description = "Recherche de médicaments par dénomination")
    @ApiResponse(responseCode = "200", description = "Résultats de recherche")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<MedicamentResponse>> searchMedicaments(
            @Parameter(description = "Terme de recherche") @RequestParam String q) {

        log.debug("Recherche de médicaments: {}", q);
        List<MedicamentResponse> medicaments = medicamentService.searchByDenomination(q);
        return ResponseEntity.ok(medicaments);
    }

    @GetMapping("/rembourses")
    @Operation(summary = "Médicaments remboursés",
            description = "Récupère les médicaments remboursés par la Sécurité sociale")
    @ApiResponse(responseCode = "200", description = "Liste des médicaments remboursés")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<MedicamentResponse>> getMedicamentsRembourses() {

        log.debug("Récupération des médicaments remboursés");
        List<MedicamentResponse> medicaments = medicamentService.findMedicamentsRembourses();
        return ResponseEntity.ok(medicaments);
    }

    @GetMapping("/surveillance")
    @Operation(summary = "Médicaments sous surveillance",
            description = "Récupère les médicaments sous surveillance renforcée")
    @ApiResponse(responseCode = "200", description = "Liste des médicaments sous surveillance")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<MedicamentResponse>> getMedicamentsSurveillance() {

        log.debug("Récupération des médicaments sous surveillance");
        List<MedicamentResponse> medicaments = medicamentService.findMedicamentsSurveillance();
        return ResponseEntity.ok(medicaments);
    }

    // ============================================
    // ENDPOINTS DE GESTION (CRUD)
    // ============================================

    @PostMapping
    @Operation(summary = "Créer un médicament",
            description = "Crée un nouveau médicament dans le référentiel")
    @ApiResponse(responseCode = "201", description = "Médicament créé avec succès")
    @ApiResponse(responseCode = "400", description = "Données invalides")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<MedicamentResponse> createMedicament(
            @Parameter(description = "Données du médicament à créer")
            @Valid @RequestBody CreateMedicamentRequest request) {

        log.info("Création d'un nouveau médicament: {}", request.getCodeCis());
        MedicamentResponse medicament = medicamentService.create(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(medicament);
    }

    @PutMapping("/{id}")
    @Operation(summary = "Modifier un médicament",
            description = "Met à jour les informations d'un médicament existant")
    @ApiResponse(responseCode = "200", description = "Médicament modifié avec succès")
    @ApiResponse(responseCode = "404", description = "Médicament non trouvé")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<MedicamentResponse> updateMedicament(
            @Parameter(description = "ID du médicament") @PathVariable UUID id,
            @Parameter(description = "Nouvelles données du médicament")
            @Valid @RequestBody UpdateMedicamentRequest request) {

        log.info("Modification du médicament: {}", id);
        MedicamentResponse medicament = medicamentService.update(id, request);
        return ResponseEntity.ok(medicament);
    }

    @PatchMapping("/{id}/desactiver")
    @Operation(summary = "Désactiver un médicament",
            description = "Désactive un médicament (soft delete)")
    @ApiResponse(responseCode = "204", description = "Médicament désactivé")
    @ApiResponse(responseCode = "404", description = "Médicament non trouvé")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> desactiverMedicament(
            @Parameter(description = "ID du médicament") @PathVariable UUID id) {

        log.info("Désactivation du médicament: {}", id);
        medicamentService.desactiver(id);
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{id}/reactiver")
    @Operation(summary = "Réactiver un médicament",
            description = "Réactive un médicament précédemment désactivé")
    @ApiResponse(responseCode = "200", description = "Médicament réactivé")
    @ApiResponse(responseCode = "404", description = "Médicament non trouvé")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<MedicamentResponse> reactiverMedicament(
            @Parameter(description = "ID du médicament") @PathVariable UUID id) {

        log.info("Réactivation du médicament: {}", id);
        MedicamentResponse medicament = medicamentService.reactiver(id);
        return ResponseEntity.ok(medicament);
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Supprimer définitivement un médicament",
            description = "Supprime définitivement un médicament (attention: irréversible)")
    @ApiResponse(responseCode = "204", description = "Médicament supprimé")
    @ApiResponse(responseCode = "404", description = "Médicament non trouvé")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteMedicament(
            @Parameter(description = "ID du médicament") @PathVariable UUID id) {

        log.warn("Suppression définitive du médicament: {}", id);
        medicamentService.deleteDefinitivement(id);
        return ResponseEntity.noContent().build();
    }

    // ============================================
    // ENDPOINTS UTILITAIRES
    // ============================================

    @GetMapping("/count")
    @Operation(summary = "Nombre de médicaments actifs",
            description = "Retourne le nombre total de médicaments actifs")
    @ApiResponse(responseCode = "200", description = "Nombre récupéré")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Long> countMedicamentsActifs() {

        long count = medicamentService.countActifs();
        return ResponseEntity.ok(count);
    }

    @GetMapping("/exists/{codeCis}")
    @Operation(summary = "Vérifier l'existence d'un médicament",
            description = "Vérifie si un médicament existe avec le code CIS donné")
    @ApiResponse(responseCode = "200", description = "Statut d'existence")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Boolean> checkMedicamentExists(
            @Parameter(description = "Code CIS à vérifier") @PathVariable String codeCis) {

        boolean exists = medicamentService.existsByCodeCis(codeCis);
        return ResponseEntity.ok(exists);
    }
}