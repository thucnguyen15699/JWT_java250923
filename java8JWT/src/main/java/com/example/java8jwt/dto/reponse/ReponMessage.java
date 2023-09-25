package com.example.java8jwt.dto.reponse;

public class ReponMessage {
    private String message;

    public ReponMessage() {
    }

    public ReponMessage(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

}
