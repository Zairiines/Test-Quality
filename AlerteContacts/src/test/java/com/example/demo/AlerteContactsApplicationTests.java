package com.example.demo;

import com.example.demo.entity.User;
import com.example.demo.entity.Entreprise;
import com.example.demo.entity.AuthRequest;
import com.example.demo.entity.LoginResponse;
import com.example.demo.Repository.UserRepository;
import com.example.demo.service.UserService;
import com.example.demo.Repository.EntrepriseRepository;
import com.example.demo.service.EntrepriseService;
import com.example.demo.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.springframework.boot.test.context.SpringBootTest;
import java.util.Optional;


@SpringBootTest
class AlerteContactsApplicationTests {

    @Mock
    private UserRepository userRepository;
    @Mock
    private EntrepriseRepository entrepriseRepository;

    @Mock
    private JwtService jwtService;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private PasswordEncoder encoder;

    @InjectMocks
    private UserService userService;
    
    @InjectMocks
    private EntrepriseService entrepriseService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void contextLoads() {
    }

    private User testUser;

    @BeforeEach
    void initializeUser() {
        testUser = new User();
        testUser.setUsername("testUser");
        testUser.setEmail("test@example.com");
        testUser.setPassword("password");
    }

    @Test
    void testAddNewUser() {
        // Préparez le comportement du mock
        when(userRepository.findUserByEmail("test@example.com")).thenReturn(Optional.empty());
        when(encoder.encode("password")).thenReturn("encodedPassword");
        when(jwtService.generateToken("test@example.com")).thenReturn("verificationToken");

        // Appelez la méthode à tester
        User result = userService.addNewUser(testUser);

        // Vérifiez les résultats
        assertEquals("encodedPassword", result.getPassword());
        assertEquals("verificationToken", result.getVerificationToken());
        assertFalse(result.isVerified());
        verify(userRepository, times(1)).save(result);
    }
    @Test
    void testVerifyUser() {
        String token = "verificationToken";
        User user = new User();
        user.setVerificationToken(token);
        user.setVerified(false);

        when(userRepository.findByVerificationToken(token)).thenReturn(Optional.of(user));

        userService.verifyUser(token);

        assertTrue(user.isVerified());
        assertNull(user.getVerificationToken());
        verify(userRepository, times(1)).save(user);
    }

    @Test
    void testLoginUser() {
        String username = "testUser";
        String password = "password";
        User user = new User();
        user.setUsername(username);
        user.setPassword("encodedPassword");

        when(userRepository.findUserByUsername(username)).thenReturn(Optional.of(user));
        when(encoder.matches(password, "encodedPassword")).thenReturn(true);
        when(jwtService.generateToken(username)).thenReturn("jwtToken");

        LoginResponse response = userService.loginUser(username, password);

        assertEquals("jwtToken", response.getToken());
        assertEquals(user, response.getUser());
    }

    @Test
    void testDeleteUser_AdminRole() {
        Long userId = 1L;
        User user = new User();
        when(userRepository.existsById(userId)).thenReturn(true);

        // Simuler un utilisateur avec le rôle ADMIN
        Authentication authentication = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(new org.springframework.security.core.userdetails.User("admin", "password", List.of(new SimpleGrantedAuthority("ADMIN"))));

        boolean result = userService.deleteUser(userId);

        assertTrue(result);
        verify(userRepository, times(1)).deleteById(userId);
    }

    @Test
    void testUpdateUser_AdminRole() {
        Long userId = 1L;
        User existingUser = new User();
        existingUser.setUsername("oldUsername");
        existingUser.setEmail("old@example.com");
        existingUser.setPassword("oldPassword");

        when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));

        // Simuler un utilisateur avec le rôle ADMIN
        Authentication authentication = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(new org.springframework.security.core.userdetails.User("admin", "password", List.of(new SimpleGrantedAuthority("ADMIN"))));

        boolean result = userService.updateUser(userId, "newUsername", "new@example.com", "newPassword");

        assertTrue(result);
        assertEquals("newUsername", existingUser.getUsername());
        assertEquals("new@example.com", existingUser.getEmail());
        assertEquals("newPassword", existingUser.getPassword());
        verify(userRepository, times(1)).save(existingUser);
    }

    

    @Test
    void testAdminLogin() {
        AuthRequest authRequest = new AuthRequest();
        authRequest.setUsername("admin");
        authRequest.setPassword("password");

        User user = new User();
        user.setUsername("admin");

        when(authenticationManager.authenticate(any())).thenReturn(mock(Authentication.class));
        when(jwtService.generateToken("admin")).thenReturn("jwtToken");
        when(userRepository.findUserByUsername("admin")).thenReturn(Optional.of(user));

        LoginResponse response = userService.adminLogin(authRequest);

        assertEquals("jwtToken", response.getToken());
        assertEquals(user, response.getUser());
    }
    
    @Test
    void testGetAllEntreprises() {
        List<Entreprise> entreprises = List.of(new Entreprise("Entreprise 1", "entreprise1@example.com", "12345"));
        
        when(entrepriseRepository.findAllActive()).thenReturn(entreprises);
        
        List<Entreprise> result = entrepriseService.getAllEntreprises();
        
        assertEquals(1, result.size());
        assertEquals("Entreprise 1", result.get(0).getName());
    }

    
    @Test
    void testGetEntrepriseByName() {
        String name = "Entreprise 1";
        Entreprise entreprise = new Entreprise(name, "entreprise1@example.com", "12345");
        
        when(entrepriseRepository.findEntrepriseByName(name)).thenReturn(Optional.of(entreprise));
        
        Optional<Entreprise> result = entrepriseService.getEntrepriseByName(name);
        
        assertTrue(result.isPresent());
        assertEquals(name, result.get().getName());
    }

    @Test
    void testAddNewEntreprise() {
        Entreprise entreprise = new Entreprise("Entreprise 2", "entreprise2@example.com", "72584987");
        
        when(entrepriseRepository.findEntrepriseByEmail("entreprise1@example.com")).thenReturn(Optional.empty());
        when(entrepriseRepository.findEntrepriseByName("Entreprise 2")).thenReturn(Optional.empty());
        when(entrepriseRepository.save(entreprise)).thenReturn(entreprise);
        
        Entreprise result = entrepriseService.addNewEntreprise(entreprise);
        
        assertEquals("Entreprise 2", result.getName());
        verify(entrepriseRepository, times(1)).save(entreprise);
    }
    
}