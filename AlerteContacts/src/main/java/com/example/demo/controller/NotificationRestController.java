package com.example.demo.controller;

import com.example.demo.service.EmailService;
import com.example.demo.service.NotificationService;
import com.example.demo.entity.NotificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@CrossOrigin("*")
public class NotificationRestController {

    @Autowired
    private NotificationService notificationService;

    @Autowired
    private EmailService emailService;

    @PostMapping("/sendNotification")
    public void sendNotification(@RequestBody NotificationRequest request) {
        notificationService.sendNotification(
            request.getUserId(),
            request.getMessage(),
            request.getType(),
            request.getEmail()
        );
    }

    @PostMapping("/SendMail/{to}/{subject}")
    public void save(@RequestBody String text, @PathVariable("to") String to, @PathVariable("subject") String subject) {
        emailService.sendSimpleMessage(to, subject, text);
    }
}
