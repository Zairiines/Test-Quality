package com.example.demo.Repository;

import com.example.demo.entity.Entreprise;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;

@Repository
public interface EntrepriseRepository extends JpaRepository<Entreprise, Long> {

    Optional<Entreprise> findEntrepriseByEmail(String email);

    //Optional<Entreprise> findEntrepriseByName(String name);
    @Query("SELECT e FROM Entreprise e WHERE e.deleted = false")
    List<Entreprise> findAllActive();
    @Query("SELECT e FROM Entreprise e WHERE e.name = :name AND e.deleted = false")
    Optional<Entreprise> findEntrepriseByName(@Param("name") String name);

}
