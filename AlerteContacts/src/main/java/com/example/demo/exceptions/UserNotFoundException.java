package com.example.demo.exceptions;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;

@SuppressWarnings("serial")
public class UserNotFoundException extends RuntimeException {
    
    public UserNotFoundException(String message) {
        super(message);
        
    }
    public UserNotFoundException(String message, DisabledException cause) {
        super(message, cause);
    }
    public UserNotFoundException(String message, LockedException cause) {
        super(message, cause);
    }
    public UserNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
