package com.example.demo.config;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.example.demo.filtre.JwtAuthFilter;
import com.example.demo.service.UserService;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final UserService userService;
    private final JwtAuthFilter jwtAuthFilter;

    public SecurityConfig(
            @Lazy UserService userService,
            JwtAuthFilter jwtAuthFilter) {
        this.userService = userService;
        this.jwtAuthFilter = jwtAuthFilter;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return userService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/server/users/register",
                    "/server/users/verify",
                    "/server/users/login",
                    "/server/users/current",
                    "/server/users/{username}",
                    "/server/users/adminLogin", 
                    "/server/users/{id}",
                    "/server/users/update/{userId}",
                    "/server/users",
                    "/api/contracts/createContract",
                    "/api/contracts/getAllContracts",
                    "/api/contracts/getContractByName/{title}",
                    "/api/contracts/getContract/{contractId}",
                    "/api/contracts/deleteContract/{contractId}",
                    "/api/contracts/updateContract/{contractId}",
                    "api/contracts/testNotifyUsersOfEndingContracts",
                    "/api/documents/upload",
                    "/api/documents",
                    "/api/documents/contract/{contractId}",
                    "/api/documents/download/{documentId}",
                    "/server/entreprises/addEntreprise",
                    "/server/entreprises",
                    "/server/entreprises/{name}",
                    "/server/entreprises/{id}",
                    "/server/entreprises/update/{id}",
                    "api/sendNotification",
                    "api/SendMail/{to}/{subject}",
                    "/websocket/**"  // Permettre l'accès non authentifié à l'endpoint WebSocket
                ).permitAll()
                .requestMatchers("/server/users/update/{userId}", "/server/users/update/{id}", "/server/entreprises/update/{id}").hasAuthority("ADMIN")
                .requestMatchers("/server/users/adminLogin").hasAuthority("ADMIN")
                .requestMatchers("/userLogin").hasAnyAuthority("ADMIN", "UTILISATEUR")
                .anyRequest().authenticated()
            )
            .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authenticationProvider(authenticationProvider())
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:4200"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Origin", "X-Requested-With", "Content-Type", "Accept", "Authorization"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
