package com.jmna.auth.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class LogoutRequest {
    private String username;

    public LogoutRequest(String username, String password) {
        this.username = username;
    }
}
