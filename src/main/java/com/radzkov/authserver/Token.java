package com.radzkov.authserver;

/**
 * @author Radzkov Andrey
 */
public class Token {
    private String token;
    private String userId;

     String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

     String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}
