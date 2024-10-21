package com.example.demo.entity;

public class Token {

    private String value;

    // Default constructor
    public Token() {
    }

    // Constructor with String parameter
    public Token(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
