package com.example.demo.Repository;


import java.util.Optional;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.demo.entity.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
	 Optional<User> findById(Long id);

    Optional<User> findUserByEmail(String email);

    Optional<User> findUserByUsername(String username);
    List<User> findByRole(String role); 
    Optional<User> findByVerificationToken(String token);
}

	

