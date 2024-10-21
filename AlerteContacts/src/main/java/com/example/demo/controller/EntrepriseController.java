package com.example.demo.controller;

import com.example.demo.entity.Entreprise;
import com.example.demo.service.EntrepriseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;
import org.springframework.security.access.AccessDeniedException;
@RestController
@CrossOrigin(origins = "*", allowedHeaders = "*")
@RequestMapping("/server/entreprises")
public class EntrepriseController {

	@Autowired
    private final EntrepriseService entrepriseService;

    public EntrepriseController(EntrepriseService entrepriseService) {
        this.entrepriseService = entrepriseService;
    }
    @GetMapping("/{name}")
    public ResponseEntity<Entreprise> getEntrepriseByName(@PathVariable String name) {
        Optional<Entreprise> entreprise = entrepriseService.getEntrepriseByName(name);
        return entreprise.map(ResponseEntity::ok)
                         .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping()
    public List<Entreprise> getAllEntreprises() {
        return entrepriseService.getAllEntreprises();
    }

    @PostMapping("/addEntreprise")
    public Entreprise postEntreprise(@RequestBody Entreprise entrprise) {
        return entrepriseService.addNewEntreprise(entrprise);}

    @DeleteMapping("/{id}")
    public ResponseEntity<String> deleteEntreprise(@PathVariable Long id) {
        try {
            entrepriseService.deleteEntreprise(id);
            return ResponseEntity.ok("Entreprise deleted successfully");
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
        } catch (AccessDeniedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
        }
    }
    @PutMapping("/update/{id}")
    public ResponseEntity<Entreprise> updateEntreprise(
            @PathVariable Long id,
            @RequestParam(required = false) String name,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String phone) {

        try {
            Optional<Entreprise> updatedEntreprise = entrepriseService.updateEntreprise(id, name, email, phone);
            return new ResponseEntity<>(updatedEntreprise.orElse(null), HttpStatus.OK);
        } catch (AccessDeniedException e) {
            return new ResponseEntity<>(null, HttpStatus.FORBIDDEN);
        } catch (IllegalStateException e) {
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        }
    }
}
