package com.example.demo.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import com.example.demo.entity.User;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class UserInfoDetails implements UserDetails {

    private static final long serialVersionUID = 1L;
    private String username;
    private String password;
    private Set<GrantedAuthority> authorities;

    public UserInfoDetails(User user) {
        this.username = user.getUsername(); // Utiliser le nom d'utilisateur au lieu de l'email
        this.password = user.getPassword();
        this.authorities = new HashSet<>();

        for (String role : user.getRole()) {  // Supposons que user.getRole() renvoie une collection
            this.authorities.add(new SimpleGrantedAuthority(role));
        }
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() { // Retourner le nom d'utilisateur
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
