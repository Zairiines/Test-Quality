package com.example.demo.entity;

public class NotificationRequest {

    private Long userId; // Ajout du champ userId
    private String email; // Remplacer destination par email
    private String message;
    private String type; // Ajout du champ type

    // Getter pour userId
    public Long getUserId() {
        return userId;
    }

    // Setter pour userId
    public void setUserId(Long userId) {
        this.userId = userId;
    }

    // Getter pour email
    public String getEmail() {
        return email;
    }

    // Setter pour email
    public void setEmail(String email) {
        this.email = email;
    }

    // Getter pour message
    public String getMessage() {
        return message;
    }

    // Setter pour message
    public void setMessage(String message) {
        this.message = message;
    }

    // Getter pour type
    public String getType() {
        return type;
    }

    // Setter pour type
    public void setType(String type) {
        this.type = type;
    }
}
