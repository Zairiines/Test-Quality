package com.example.demo.controller;

import com.example.demo.entity.Entreprise;
import com.example.demo.entity.Contract;
import com.example.demo.service.ContractService;
import com.example.demo.service.EntrepriseService;
import com.example.demo.dto.ContractDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/contracts")
public class ContractController {

    @Autowired
    private final ContractService contractService;

    @Autowired
    private final EntrepriseService entrepriseService;

    public ContractController(ContractService contractService, EntrepriseService entrepriseService) {
        this.contractService = contractService;
        this.entrepriseService = entrepriseService;
    }

    @GetMapping("/getAllContracts")
    public ResponseEntity<List<ContractDTO>> getAllContracts() {
        List<ContractDTO> contractDTOs = contractService.getAllContracts();
        return ResponseEntity.ok(contractDTOs);
    }

    @GetMapping("/getContract/{contractId}")
    public ResponseEntity<Contract> getContractById(@PathVariable Long contractId) {
        Contract contract = contractService.getContractById(contractId);
        if (contract != null) {
            return ResponseEntity.ok(contract);
        } else {
            return ResponseEntity.notFound().build();
        }
    }
    @GetMapping("/getContractByName/{title}")
    public ResponseEntity<Contract> getContractByName(@PathVariable String title) {
        Optional<Contract> contract = contractService.getContractByName(title);
        
        return contract.map(ResponseEntity::ok)  // If contract is present, return it with HTTP 200 OK
                       .orElseGet(() -> ResponseEntity.notFound().build());  // If not found, return HTTP 404
    }



    @PostMapping("/createContract")
    public ResponseEntity<?> createContract(@RequestBody ContractDTO request) {
        if (request.getUserId() == null || request.getEntrepriseName() == null || request.getDateDebut() == null || request.getDateFin() == null || request.getTitle() == null || request.getDescription() == null) {
            return ResponseEntity.badRequest().body("Les champs userId, entrepriseName, dateDebut, dateFin, title et description sont requis.");
        }

        try {
            // Trouver l'entreprise
            Optional<Entreprise> optionalEntreprise = entrepriseService.getEntrepriseByName(request.getEntrepriseName());
            
            if (optionalEntreprise.isEmpty()) {
                return ResponseEntity.badRequest().body("Entreprise non trouvée avec le nom spécifié.");
            }

            Entreprise entreprise = optionalEntreprise.get();
            
            // Créer un nouvel objet Contract
            Contract contract = new Contract();
            contract.setDateDebut(request.getDateDebut());
            contract.setDateFin(request.getDateFin());
            contract.setTitle(request.getTitle());
            contract.setDescription(request.getDescription());

            // Appeler le service pour créer le contrat
            Contract createdContract = contractService.createContractForEntreprise(
                    request.getUserId(), entreprise, contract
            );

            return ResponseEntity.ok(createdContract);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Erreur lors de la création du contrat : " + e.getMessage());
        }
    }


    @PutMapping("/updateContract/{contractId}")
    public ResponseEntity<Contract> updateContract(@PathVariable Long contractId, @RequestBody Contract updatedContract) {
        Contract updated = contractService.updateContract(contractId, updatedContract);
        return ResponseEntity.ok(updated);
    }

    @DeleteMapping("/deleteContract/{contractId}")
    public ResponseEntity<String> deleteContract(@PathVariable Long contractId) {
        try {
            contractService.deleteContract(contractId);
            return ResponseEntity.status(HttpStatus.OK).body("Contract with ID: " + contractId + " has been deleted successfully");
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
        }
    }

    @PostMapping("/testNotifyUsersOfEndingContracts")
    public ResponseEntity<String> testNotifyUsersOfEndingContracts() {
        contractService.notifyUsersOfEndingContracts();
        return ResponseEntity.ok("Notification test completed.");
    }
}
