package com.example.demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;
import com.example.demo.entity.User;
import com.example.demo.entity.Notification;
import com.example.demo.Repository.NotificationRepository;
import com.example.demo.Repository.UserRepository;

import java.time.LocalDate;
import java.time.LocalTime;

@Service
public class NotificationService {

    @Autowired
    private final SimpMessagingTemplate messagingTemplate;

    @Autowired
    private final EmailService emailService;  // Utilisez EmailService au lieu de JavaMailSender

    private final NotificationRepository notificationRepository;
    private final UserRepository userRepository;

    public NotificationService(SimpMessagingTemplate messagingTemplate,
                               EmailService emailService,  // Injection du service EmailService
                               NotificationRepository notificationRepository,
                               UserRepository userRepository) {
        this.messagingTemplate = messagingTemplate;
        this.emailService = emailService;
        this.notificationRepository = notificationRepository;
        this.userRepository = userRepository;
    }

    public void sendNotification(Long userId, String message, String type, String email) {
        // Récupérer l'utilisateur à partir de l'identifiant
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + userId));

        // Enregistrer la notification dans la base de données
        Notification notification = new Notification();
        notification.setUser(user);  // Associez l'utilisateur à la notification
        notification.setContenu(message);
        notification.setDate(LocalDate.now());
        notification.setTime(LocalTime.now());
        notification.setType(type);
        notificationRepository.save(notification);

        // Envoyer la notification en temps réel à l'utilisateur via WebSocket
        messagingTemplate.convertAndSendToUser(userId.toString(), "/notifications", message);

        // Utiliser EmailService pour envoyer un e-mail
        emailService.sendSimpleMessage(email, "Notification: " + type, message);
    }
}
