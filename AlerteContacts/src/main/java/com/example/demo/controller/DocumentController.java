package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import com.example.demo.dto.DocumentDTO;
import com.example.demo.service.DocumentService;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    @Autowired
    private DocumentService documentService;

    @PostMapping("/upload")
    public ResponseEntity<String> uploadDocument(@RequestParam("file") MultipartFile file,
                                                 @RequestParam("title") String title,
                                                 @RequestParam("description") String description,
                                                 @RequestParam("type") String type,
                                                 @RequestParam("contractId") Long contractId) {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("Le fichier est requis.");
        }

        try {
            documentService.saveDocument(file, title, description, type, contractId);
            return ResponseEntity.ok("Document téléchargé avec succès.");
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Échec du téléchargement du document : " + e.getMessage());
        }
    }

    @GetMapping("/download/{documentId}")
    public ResponseEntity<Resource> downloadDocument(@PathVariable Long documentId) {
        System.out.println("Demande de téléchargement du document avec l'ID: " + documentId);

        // Rechercher le document en utilisant l'ID
        DocumentDTO documentDTO = documentService.getAllDocuments().stream()
                .filter(doc -> doc.getDocumentId().equals(documentId))
                .findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Document non trouvé avec l'ID " + documentId));

        System.out.println("Document trouvé: " + documentDTO);

        // Charger le fichier en utilisant le chemin (`path`)
        Resource resource = documentService.loadFileAsResourceByPath(documentDTO.getPath());
        
        System.out.println("Chemin du fichier: " + documentDTO.getPath());
        System.out.println("Existence du fichier: " + resource.exists());
        System.out.println("Lisibilité du fichier: " + resource.isReadable());
        
        if (!resource.exists() || !resource.isReadable()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Fichier non trouvable ou illisible avec le chemin " + documentDTO.getPath());
        }

        // Déterminer le type de contenu du fichier
        String contentType;
        try {
            contentType = Files.probeContentType(Paths.get(documentDTO.getPath()));
        } catch (IOException e) {
            contentType = "application/octet-stream"; // Valeur par défaut si le type MIME ne peut pas être déterminé
        }

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resource.getFilename() + "\"")
                .body(resource);
    }

    @GetMapping
    public ResponseEntity<List<DocumentDTO>> getDocuments() {
        List<DocumentDTO> documents = documentService.getAllDocuments();
        return ResponseEntity.ok(documents);
    }

    @GetMapping("/contract/{contractId}")
    public ResponseEntity<List<DocumentDTO>> getDocumentsByContractId(@PathVariable Long contractId) {
        List<DocumentDTO> documents = documentService.getDocumentsByContractId(contractId);
        if (documents.isEmpty()) {
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.ok(documents);
    }
}
