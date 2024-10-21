package com.example.demo.dto;

import com.example.demo.entity.Contract;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class ContractMapper {

    public List<ContractDTO> convertToDTOs(List<Contract> contracts) {
        return contracts.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    public ContractDTO convertToDTO(Contract contract) {
        ContractDTO dto = new ContractDTO();
        dto.setContractId(contract.getContractId());
        dto.setDateDebut(contract.getDateDebut());
        dto.setDateFin(contract.getDateFin());
        dto.setEntrepriseName(contract.getEntreprise().getName()); // Assurez-vous que getName() existe
        dto.setUserId(contract.getUser().getId());
        dto.setTitle(contract.getTitle()); // Ajouter le titre
        dto.setDescription(contract.getDescription()); // Ajouter la description
        return dto;
    }
}
