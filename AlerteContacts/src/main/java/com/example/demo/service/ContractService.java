package com.example.demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.example.demo.Repository.ContractRepository;
import com.example.demo.Repository.EntrepriseRepository;
import com.example.demo.Repository.UserRepository;
import com.example.demo.entity.Contract;
import com.example.demo.entity.User;
import com.example.demo.entity.Entreprise;
import com.example.demo.dto.ContractDTO;
import com.example.demo.dto.ContractMapper;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import org.springframework.scheduling.annotation.EnableScheduling;
@Service
@Transactional
@EnableScheduling
public class ContractService {

    @Autowired
    private final UserRepository userRepository;
    private final EntrepriseRepository entrepriseRepository;
    private final ContractRepository contractRepository;
    private final ContractMapper contractMapper;
    private final NotificationService notificationService;

    public ContractService(UserRepository userRepository, 
                           EntrepriseRepository entrepriseRepository,
                           ContractRepository contractRepository, 
                           ContractMapper contractMapper,
                           NotificationService notificationService) {
        this.userRepository = userRepository;
        this.entrepriseRepository = entrepriseRepository;
        this.contractRepository = contractRepository;
        this.contractMapper = contractMapper;
        this.notificationService = notificationService;
    }

    public List<ContractDTO> getAllContracts() {
        List<Contract> contracts = contractRepository.findAll();
        return contractMapper.convertToDTOs(contracts);
    }

    public Contract getContractById(Long contractId) {
        Optional<Contract> contractOptional = contractRepository.findById(contractId);
        return contractOptional.orElse(null);
    }
    
    public Optional<Contract> getContractByName(String title) {
        List<Contract> contracts = contractRepository.findByTitle(title);

        if (contracts.isEmpty()) {
            return Optional.empty();  // Return an empty Optional if no contracts found
        }

        return Optional.of(contracts.get(0));  // Return the first contract found wrapped in an Optional
    }


    public Contract createContractForEntreprise(Long userId, Entreprise entreprise, Contract contract) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalStateException("Utilisateur non trouvé avec l'ID: " + userId));

        // Vous avez déjà l'objet Entreprise, donc pas besoin de rechercher à nouveau
        contract.setUser(user);
        contract.setEntreprise(entreprise);

        // Enregistrement du contrat
        Contract savedContract = contractRepository.save(contract);

        return savedContract;
    }

    public Contract updateContract(Long contractId, Contract updatedContract) {
        Contract existingContract = contractRepository.findById(contractId)
                .orElseThrow(() -> new IllegalStateException("Contract not found with ID: " + contractId));

        existingContract.setDateDebut(updatedContract.getDateDebut());
        existingContract.setDateFin(updatedContract.getDateFin());
        existingContract.setTitle(updatedContract.getTitle());
        existingContract.setDescription(updatedContract.getDescription());

        return contractRepository.save(existingContract);
    }

    public void deleteContract(Long contractId) {
        Contract contract = contractRepository.findById(contractId)
                .orElseThrow(() -> new IllegalStateException("Contract not found with ID: " + contractId));

        contractRepository.delete(contract);
    }

    @Scheduled(cron = "0 0 9 * * ?") // Exécution quotidienne à 9h00
    public void notifyUsersOfEndingContracts() {
        LocalDate today = LocalDate.now();
        List<Contract> contracts = contractRepository.findAll();

        for (Contract contract : contracts) {
            LocalDate endDate = contract.getDateFin();
            User user = contract.getUser();
            String contractName = contract.getTitle(); // Assurez-vous que `Contract` a une méthode `getName()`

            if (endDate != null && user != null) {
                long daysUntilEnd = java.time.temporal.ChronoUnit.DAYS.between(today, endDate);

                String message = null;
                String type = "Rappel de contrat";

                // Déterminer le message en fonction du nombre de jours restants
                if (daysUntilEnd == 60) {
                    message = "Votre contrat \"" + contractName + "\" se termine dans 60 jours.";
                } else if (daysUntilEnd == 30) {
                    message = "Votre contrat \"" + contractName + "\" se termine dans 30 jours.";
                } else if (daysUntilEnd == 14) {
                    message = "Votre contrat \"" + contractName + "\" se termine dans 14 jours.";
                } else if (daysUntilEnd <= 7) {
                    message = "Votre contrat \"" + contractName + "\" se termine le " + endDate + ". Veuillez prendre les mesures nécessaires.";
                }

                // Envoyer la notification si un message est défini
                if (message != null) {
                    // Passer l'email de l'utilisateur à la méthode de notification
                    String email = user.getEmail(); // Assurez-vous que `User` a une méthode `getEmail()`
                    notificationService.sendNotification(user.getId(), message, type, email);
                }
            }
        }
    }

}
