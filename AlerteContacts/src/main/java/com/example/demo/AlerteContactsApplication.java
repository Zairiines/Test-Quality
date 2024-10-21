package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@Configuration
@ComponentScan(basePackages = {"com.example.demo"})
public class AlerteContactsApplication {

	public static void main(String[] args) {
		SpringApplication.run(AlerteContactsApplication.class, args);
		
	    }
	}


