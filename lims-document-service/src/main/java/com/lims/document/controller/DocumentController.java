package com.lims.document.controller;

import com.lims.document.dto.DocumentDTO;
import com.lims.document.dto.UploadRequestDTO;
import com.lims.document.entity.Document;
import com.lims.document.service.DocumentService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/documents")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Documents", description = "API de gestion des documents et fichiers")
@SecurityRequirement(name = "Bearer Authentication")
public class DocumentController {

    private final DocumentService documentService;

    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Upload d'un document",
            description = "Upload un fichier (image ou PDF) vers le stockage MinIO")
    @ApiResponse(responseCode = "201", description = "Document uploadé avec succès")
    @ApiResponse(responseCode = "400", description = "Données invalides")
    @ApiResponse(responseCode = "413", description = "Fichier trop volumineux")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<DocumentDTO> uploadDocument(
            @RequestPart("file") MultipartFile file,
            @RequestPart("metadata") @Valid UploadRequestDTO request,
            Authentication authentication) {

        UUID uploadedBy = UUID.fromString(authentication.getName());
        DocumentDTO result = documentService.uploadDocument(file, request, uploadedBy);

        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Récupérer les métadonnées d'un document",
            description = "Récupère les informations d'un document par son ID")
    @ApiResponse(responseCode = "200", description = "Document trouvé")
    @ApiResponse(responseCode = "404", description = "Document non trouvé")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<DocumentDTO> getDocument(@PathVariable UUID id) {
        DocumentDTO document = documentService.getDocumentById(id);
        return ResponseEntity.ok(document);
    }

    @GetMapping("/{id}/download")
    @Operation(summary = "Télécharger un document",
            description = "Télécharge le contenu binaire d'un document")
    @ApiResponse(responseCode = "200", description = "Document téléchargé",
            content = @Content(mediaType = "application/octet-stream"))
    @ApiResponse(responseCode = "404", description = "Document non trouvé")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<byte[]> downloadDocument(@PathVariable UUID id) {
        DocumentDTO document = documentService.getDocumentById(id);
        byte[] fileContent = documentService.downloadDocument(id);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType(document.getContentType()));
        headers.setContentDispositionFormData("attachment", document.getOriginalFilename());
        headers.setContentLength(fileContent.length);

        return ResponseEntity.ok()
                .headers(headers)
                .body(fileContent);
    }

    @GetMapping("/{id}/url")
    @Operation(summary = "Générer une URL de téléchargement temporaire",
            description = "Génère une URL présignée valide pendant 1 heure")
    @ApiResponse(responseCode = "200", description = "URL générée avec succès")
    @ApiResponse(responseCode = "404", description = "Document non trouvé")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<String> generateDownloadUrl(
            @PathVariable UUID id,
            @RequestParam(defaultValue = "60") int expirationMinutes) {

        String url = documentService.generateDownloadUrl(id, expirationMinutes);
        return ResponseEntity.ok(url);
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Supprimer un document",
            description = "Suppression logique d'un document (soft delete)")
    @ApiResponse(responseCode = "204", description = "Document supprimé avec succès")
    @ApiResponse(responseCode = "404", description = "Document non trouvé")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SECRETAIRE')")
    public ResponseEntity<Void> deleteDocument(@PathVariable UUID id, Authentication authentication) {
        UUID deletedBy = UUID.fromString(authentication.getName());
        documentService.softDeleteDocument(id, deletedBy);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/my-documents")
    @Operation(summary = "Récupérer mes documents",
            description = "Liste paginée des documents uploadés par l'utilisateur connecté")
    @ApiResponse(responseCode = "200", description = "Liste des documents")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SECRETAIRE') or hasRole('PRELEVEUR')")
    public ResponseEntity<Page<DocumentDTO>> getMyDocuments(
            Pageable pageable, Authentication authentication) {

        UUID userId = UUID.fromString(authentication.getName());
        Page<DocumentDTO> documents = documentService.getDocumentsByUser(userId, pageable);
        return ResponseEntity.ok(documents);
    }

    @GetMapping("/patient/{patientId}")
    @Operation(summary = "Récupérer les documents d'un patient",
            description = "Liste tous les documents associés à un patient")
    @ApiResponse(responseCode = "200", description = "Liste des documents du patient")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SECRETAIRE')")
    public ResponseEntity<List<DocumentDTO>> getPatientDocuments(@PathVariable UUID patientId) {
        List<DocumentDTO> documents = documentService.getDocumentsByPatient(patientId);
        return ResponseEntity.ok(documents);
    }

    @GetMapping("/type/{documentType}")
    @Operation(summary = "Récupérer les documents par type",
            description = "Liste tous les documents d'un type spécifique")
    @ApiResponse(responseCode = "200", description = "Liste des documents du type demandé")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<DocumentDTO>> getDocumentsByType(
            @PathVariable Document.DocumentType documentType) {

        List<DocumentDTO> documents = documentService.getDocumentsByType(documentType);
        return ResponseEntity.ok(documents);
    }
}