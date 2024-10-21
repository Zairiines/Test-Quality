package com.example.demo.service;

import com.example.demo.entity.User;
import com.example.demo.Repository.UserRepository;
import com.example.demo.exceptions.UserNotFoundException;
import com.example.demo.entity.AuthRequest;
//import com.example.demo.entity.Token;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.access.AccessDeniedException;

import java.util.List;
import java.util.Optional;
import com.example.demo.entity.LoginResponse;
@Service
public class UserService implements UserDetailsService {

    @Autowired
    private PasswordEncoder encoder;
    
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtService jwtService;

    @Autowired
    @Lazy
    private AuthenticationManager authenticationManager;

    @Autowired
    private JavaMailSender mailSender;

    @Value("${jwt.secret}")
    private String secret;

    @Transactional
    public List<User> getUsers() {
        return userRepository.findAll();
    }

    public User getUser(String username) {
        Optional<User> userOptional = userRepository.findUserByUsername(username);
        return userOptional.orElseThrow(() -> new UserNotFoundException("User not found with username: " + username));
    }

    @Transactional
    public User addNewUser(User user) {
        user.setPassword(encoder.encode(user.getPassword()));

        Optional<User> existingEmail = userRepository.findUserByEmail(user.getEmail());
        if (existingEmail.isPresent()) {
            throw new IllegalStateException("Email taken");
        }

        String verificationToken = jwtService.generateToken(user.getEmail());
        user.setVerificationToken(verificationToken);
        user.setVerified(false);

        userRepository.save(user);
        
        
        // Send verification email
        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo(user.getEmail());
        mailMessage.setSubject("Complete Registration!");
        mailMessage.setFrom("noreply@domain.com");
        mailMessage.setText("To confirm your account, please click here : "
                + "http://localhost:8000/verify?token=" + verificationToken);

        mailSender.send(mailMessage);

        return user;
    }


    public void verifyUser(String token) {
        Optional<User> userOptional = userRepository.findByVerificationToken(token);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            user.setVerified(true);
            user.setVerificationToken(null);
            userRepository.save(user);
        } else {
            throw new IllegalStateException("Invalid token");
        }
    }

    public LoginResponse loginUser(String username, String password) {
        User user = userRepository.findUserByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found with username: " + username));

        if (!encoder.matches(password, user.getPassword())) {
            throw new IllegalStateException("Invalid credentials");
        }

        String token = jwtService.generateToken(user.getUsername());

        return new LoginResponse(token, user);
    }


    public boolean deleteUser(Long id) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof UserDetails) {
                UserDetails userDetails = (UserDetails) principal;

                if (userDetails.getAuthorities().stream().anyMatch(r -> r.getAuthority().equals("ADMIN"))) {
                    if (userRepository.existsById(id)) {
                        userRepository.deleteById(id);
                        return true;
                    } else {
                        throw new IllegalStateException("User with id " + id + " does not exist");
                    }
                }
            }
        }

        throw new IllegalStateException("Non autorisé : Seuls les ADMIN peuvent supprimer des utilisateurs");
    }

    @Transactional
    public boolean updateUser(Long userId, String username, String email, String password) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof UserDetails) {
                UserDetails userDetails = (UserDetails) principal;

                if (userDetails.getAuthorities().stream().anyMatch(r -> r.getAuthority().equals("ADMIN"))) {
                    // Trouver l'utilisateur existant
                    User existingUser = userRepository.findById(userId)
                            .orElseThrow(() -> new IllegalStateException("User with id " + userId + " does not exist"));

                    // Mettre à jour les détails de l'utilisateur
                    existingUser.setUsername(username);
                    existingUser.setEmail(email);
                    existingUser.setPassword(password); // Assurez-vous que le mot de passe est correctement encodé

                    userRepository.save(existingUser);
                    return true; // Mise à jour réussie
                } else {
                    throw new AccessDeniedException("Non autorisé : Seuls les ADMIN peuvent mettre à jour des utilisateurs");
                }
            } else {
                throw new AccessDeniedException("Non autorisé : Seuls les ADMIN peuvent mettre à jour des utilisateurs");
            }
        } else {
            throw new AccessDeniedException("Non autorisé : Seuls les ADMIN peuvent mettre à jour des utilisateurs");
        }
    }


    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UserNotFoundException {
        User user = userRepository.findUserByUsername(username)
            .orElseThrow(() -> new UserNotFoundException("User not found with username: " + username));
        return new UserInfoDetails(user);
    }


    public LoginResponse adminLogin(AuthRequest authRequest) {
        try {
            // Authenticate the user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));

            // Load user details
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            // Check for ADMIN role
            boolean isAdmin = userDetails.getAuthorities().stream()
                    .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ADMIN"));

            if (!isAdmin) {
                throw new RuntimeException("User does not have admin privileges");
            }

            // Generate JWT token
            final String token = jwtService.generateToken(userDetails.getUsername());
            
            // Fetch user entity by username
            User user = userRepository.findUserByUsername(authRequest.getUsername())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            return new LoginResponse(token, user);

        } catch (DisabledException e) {
            throw new RuntimeException("User is disabled", e);
        } catch (BadCredentialsException e) {
            throw new RuntimeException("Invalid credentials", e);
        } catch (Exception e) {
            throw new RuntimeException("Authentication failed: " + e.getMessage(), e);
        }
    }




}
