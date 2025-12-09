package com.jmna.auth.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class LoginResponse {
    private String message;
    private String provider;
    private String accessToken;
    private String refreshToken;

    @Builder
    public LoginResponse(String message, String provider, String accessToken, String refreshToken) {
        this.message = message;
        this.provider = provider;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }
}
