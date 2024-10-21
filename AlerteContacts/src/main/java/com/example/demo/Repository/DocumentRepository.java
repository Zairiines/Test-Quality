package com.example.demo.Repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.example.demo.entity.Document;
import com.example.demo.entity.Contract;

import java.util.List;
import java.util.Optional;

@Repository
public interface DocumentRepository extends JpaRepository<Document, Long> {
    Optional<Document> findByTitle(String title);
    List<Document> findByContract(Contract contract);
    public List<Document> findByContract_ContractId(Long contractId);

}
