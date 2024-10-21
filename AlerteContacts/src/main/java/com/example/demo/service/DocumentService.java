package com.example.demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;
import com.example.demo.entity.Contract;
import com.example.demo.entity.Document;
import com.example.demo.dto.DocumentDTO;
import com.example.demo.Repository.DocumentRepository;
import com.example.demo.Repository.ContractRepository;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class DocumentService {

    @Value("${file.upload-dir}")
    private String uploadDir;

    @Autowired
    private DocumentRepository documentRepository;

    @Autowired
    private ContractRepository contractRepository;

    @PostConstruct
    public void init() {
        try {
            Files.createDirectories(Paths.get(uploadDir));
        } catch (IOException e) {
            throw new RuntimeException("Impossible de créer le répertoire de téléchargement !", e);
        }
    }

    public String storeFile(MultipartFile file) throws IOException {
        String originalFileName = StringUtils.cleanPath(Objects.requireNonNull(file.getOriginalFilename()));
        String fileName = generateFileName(originalFileName);

        Path targetLocation = Paths.get(uploadDir).resolve(fileName);
        Files.copy(file.getInputStream(), targetLocation);

        return fileName;
    }

    public Resource loadFileAsResource(String fileName) {
        try {
            Path filePath = Paths.get(uploadDir).resolve(fileName).normalize();
            Resource resource = new UrlResource(filePath.toUri());
            if (resource.exists()) {
                return resource;
            } else {
                throw new RuntimeException("Fichier non trouvé " + fileName);
            }
        } catch (MalformedURLException ex) {
            throw new RuntimeException("Fichier non trouvé " + fileName, ex);
        }
    }

    public Resource loadFileAsResourceByPath(String path) {
        try {
            Path filePath = Paths.get(path).normalize();
            Resource resource = new UrlResource(filePath.toUri());
            if (resource.exists()) {
                return resource;
            } else {
                throw new RuntimeException("Fichier non trouvé au chemin : " + path);
            }
        } catch (MalformedURLException ex) {
            throw new RuntimeException("Fichier non trouvé au chemin : " + path, ex);
        }
    }

    public DocumentDTO saveDocument(MultipartFile file, String title, String description, String type, Long contractId) throws IOException {
        Optional<Contract> optionalContract = contractRepository.findById(contractId);
        if (!optionalContract.isPresent()) {
            throw new IllegalArgumentException("Contrat non trouvé avec l'ID : " + contractId);
        }
        Contract contract = optionalContract.get();

        Document document = new Document();
        document.setTitle(title);
        document.setDescription(description);
        document.setType(type);
        document.setContract(contract);

        // Stocker le fichier et obtenir le nom du fichier
        String fileName = storeFile(file);
        document.setFileName(fileName);

        // Définir le chemin du fichier dans l'entité Document
        Path filePath = Paths.get(uploadDir).resolve(fileName).toAbsolutePath();
        document.setPath(filePath.toString());

        // Sauvegarder le document
        Document savedDocument = documentRepository.save(document);

        // Convertir en DTO avant de retourner
        return convertToDTO(savedDocument);
    }

    public List<DocumentDTO> getAllDocuments() {
        return documentRepository.findAll().stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    public List<DocumentDTO> getDocumentsByContractId(Long contractId) {
        return documentRepository.findByContract_ContractId(contractId).stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    private String generateFileName(String originalFileName) {
        return System.currentTimeMillis() + "_" + originalFileName;
    }

    private DocumentDTO convertToDTO(Document document) {
        DocumentDTO dto = new DocumentDTO();
        dto.setDocumentId(document.getDocumentId());
        dto.setTitle(document.getTitle());
        dto.setDescription(document.getDescription());
        dto.setType(document.getType());
        dto.setPath(document.getPath()); // Ajout du chemin
        return dto;
    }
}
