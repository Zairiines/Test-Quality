package com.example.demo.controller;

import com.example.demo.entity.User;
import org.springframework.security.core.Authentication;

import com.example.demo.exceptions.UserNotFoundException;
import com.example.demo.entity.AuthRequest;
//import com.example.demo.entity.Token;
import com.example.demo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import java.util.List;
import com.example.demo.entity.LoginResponse;
@RestController
@RequestMapping("/server/users")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping
    public ResponseEntity<List<User>> getUsers() {
        List<User> users = userService.getUsers();
        return ResponseEntity.ok(users);
    }

    @GetMapping("/{username}")
    public ResponseEntity<User> getUser(@PathVariable String username) {
        User user = userService.getUser(username);
        return ResponseEntity.ok(user);
    }

    @PostMapping("/register")
    public ResponseEntity<User> registerUser(@Valid @RequestBody User user) {
        User newUser = userService.addNewUser(user);
        return ResponseEntity.ok(newUser);
    }

    @GetMapping("/verify")
    public ResponseEntity<String> verifyUser(@RequestParam String token) {
        userService.verifyUser(token);
        return ResponseEntity.ok("User verified successfully.");
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody AuthRequest authRequest) {
        try {
            LoginResponse loginResponse = userService.loginUser(authRequest.getUsername(), authRequest.getPassword());
            return ResponseEntity.ok(loginResponse);
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found with username: " + authRequest.getUsername());
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Authentication failed");
        }
    }


    @DeleteMapping("/{id}")
    public ResponseEntity<String> deleteUser(@PathVariable Long id) {
        try {
            boolean deleted = userService.deleteUser(id);
            if (deleted) {
                return ResponseEntity.ok("Utilisateur supprimé avec succès");
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Utilisateur non trouvé");
            }
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
        }
    }
    

    @PutMapping("/update/{userId}")
    public ResponseEntity<String> updateUser(
            @PathVariable Long userId,
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String password) {
        
        try {
            userService.updateUser(userId, username, email, password);
            return ResponseEntity.ok("User updated successfully");
        } catch (IllegalStateException e) {
            return ResponseEntity.status(403).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal Server Error: " + e.getMessage());
        }
    }

    @PostMapping("/adminLogin")
    public ResponseEntity<?> adminLogin(@RequestBody AuthRequest authRequest) {
        try {
            LoginResponse loginResponse = userService.adminLogin(authRequest);
            return ResponseEntity.ok(loginResponse);
        } catch (RuntimeException e) {
            // Handle specific exceptions or general RuntimeException
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        } catch (Exception e) {
            // Handle other potential exceptions
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred: " + e.getMessage());
        }
    }
    @GetMapping("/current")
    public ResponseEntity<User> getCurrentUser(Authentication authentication) {
        // Récupérez le nom d'utilisateur à partir de l'authentification
        String username = authentication.getName();
        
        // Utilisez le service pour obtenir les informations de l'utilisateur
        User user = userService.getUser(username);
        
        return ResponseEntity.ok(user);
    }


}
