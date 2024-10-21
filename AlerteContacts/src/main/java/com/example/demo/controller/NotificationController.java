package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.stereotype.Controller;

import com.example.demo.service.NotificationService;
import com.example.demo.entity.NotificationRequest;

@Controller
public class NotificationController {

    @Autowired
    private final NotificationService notificationService;
   
    public NotificationController(NotificationService notificationService) {
        this.notificationService = notificationService;
    }

    @MessageMapping("/notify")
    public void send(NotificationRequest notificationRequest) {
        // Appeler la méthode sendNotification avec l'adresse e-mail
        notificationService.sendNotification(
            notificationRequest.getUserId(),
            notificationRequest.getMessage(),
            notificationRequest.getType(),
            notificationRequest.getEmail() // Inclure l'adresse e-mail dans l'appel
        );
    }
}
