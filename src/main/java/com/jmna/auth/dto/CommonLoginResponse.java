package com.jmna.auth.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
public class CommonLoginResponse extends CommonRefreshResponse {
    private String refreshToken;
    private String provider;

    @Builder
    public CommonLoginResponse(String message, String accessToken, String refreshToken, String provider) {
        super(message, accessToken);
        this.refreshToken = refreshToken;
        this.provider = provider;
    }
}
