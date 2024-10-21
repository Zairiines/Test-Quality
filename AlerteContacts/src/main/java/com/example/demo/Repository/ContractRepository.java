package com.example.demo.Repository;

import com.example.demo.entity.Contract;
import com.example.demo.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ContractRepository extends JpaRepository<Contract, Long> {

    List<Contract> findByUser(User user);
    List<Contract> findByTitle(String title); 
}


