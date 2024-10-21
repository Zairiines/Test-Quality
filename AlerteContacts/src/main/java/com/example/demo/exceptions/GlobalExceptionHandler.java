package com.example.demo.exceptions;

import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@RestControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(UserNotFoundException.class)
    public String exceptionHandler(UserNotFoundException unfe) {
        return "UserNotFoundException: " + unfe.getMessage();
    }
}

