package com.example.demo.service;

import com.example.demo.entity.Entreprise;
import com.example.demo.Repository.EntrepriseRepository;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.access.AccessDeniedException;
@Service
public class EntrepriseService {
	@Autowired
    private final EntrepriseRepository entrepriseRepository;

    
    public EntrepriseService(EntrepriseRepository entrepriseRepository) {
        this.entrepriseRepository = entrepriseRepository;
    }

    @Transactional(readOnly = true)
    public List<Entreprise> getAllEntreprises() {
        return entrepriseRepository.findAllActive();
    }

    @Transactional(readOnly = true)
    public Optional<Entreprise> getEntrepriseByName(String name) {
        return entrepriseRepository.findEntrepriseByName(name);
    }
    public Entreprise findByName(String name) {
        return getEntrepriseByName(name)
                .orElseThrow(() -> new RuntimeException("Entreprise non trouvée avec le nom: " + name));
    }

    @Transactional
    public Entreprise addNewEntreprise(Entreprise entreprise) {
        Optional<Entreprise> existingEmail = entrepriseRepository.findEntrepriseByEmail(entreprise.getEmail());
        if (existingEmail.isPresent()) {
            throw new IllegalStateException("Email taken");
        }

        Optional<Entreprise> existingName = entrepriseRepository.findEntrepriseByName(entreprise.getName());
        if (existingName.isPresent()) {
            throw new IllegalStateException("Name taken");
        }

        return entrepriseRepository.save(entreprise);
    }

       /*@Transactional
       public void deleteEntreprise(Long id) {
        if (!entrepriseRepository.existsById(id)) {
            throw new IllegalStateException("Entreprise with id " + id + " does not exist");
        }
        entrepriseRepository.deleteById(id);
       }*/
    
    @Transactional
    public void deleteEntreprise(Long id) {
        // Vérifiez si l'utilisateur actuel a le rôle ADMIN
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!authentication.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ADMIN"))) {
            throw new AccessDeniedException("Access denied: only admins can delete");
        }

        Optional<Entreprise> entrepriseOptional = entrepriseRepository.findById(id);
        if (entrepriseOptional.isEmpty()) {
            throw new IllegalStateException("Entreprise with id " + id + " does not exist");
        }

        Entreprise entreprise = entrepriseOptional.get();
        entreprise.setDeleted(true);
        entrepriseRepository.save(entreprise);
    }

    @Transactional
    public Optional<Entreprise> updateEntreprise(Long id, String name, String email, String phone) {
        // Vérifier si l'utilisateur a le rôle ADMIN
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ADMIN"));

        if (!isAdmin) {
            throw new AccessDeniedException("Access denied: only admins can update");
        }

        Entreprise entreprise = entrepriseRepository.findById(id)
                .orElseThrow(() -> new IllegalStateException("Entreprise not found with ID: " + id));

        if (name != null && !name.equals(entreprise.getName()) && !name.isEmpty()) {
            Optional<Entreprise> existingName = entrepriseRepository.findEntrepriseByName(name);
            if (existingName.isPresent()) {
                throw new IllegalStateException("Name taken");
            }
            entreprise.setName(name);
        }

        if (email != null && !email.equals(entreprise.getEmail()) && !email.isEmpty()) {
            Optional<Entreprise> existingEmail = entrepriseRepository.findEntrepriseByEmail(email);
            if (existingEmail.isPresent()) {
                throw new IllegalStateException("Email taken");
            }
            entreprise.setEmail(email);
        }

        if (phone != null && !phone.equals(entreprise.getPhone()) && !phone.isEmpty()) {
            entreprise.setPhone(phone);
        }

        return Optional.of(entrepriseRepository.save(entreprise));
    }
}

