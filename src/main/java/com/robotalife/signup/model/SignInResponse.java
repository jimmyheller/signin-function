package com.robotalife.signup.model;

import java.util.UUID;

public class SignInResponse {
    private final UUID id;
    private final String username;
    private final String token;

    protected SignInResponse(UUID id, String username, String token) {
        this.id = id;
        this.username = username;
        this.token = token;
    }

    public static SignInResponse newInstance(UUID id, String username, String token) {
        return new SignInResponse(id, username, token);
    }

    public UUID getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getToken() {
        return token;
    }
}
