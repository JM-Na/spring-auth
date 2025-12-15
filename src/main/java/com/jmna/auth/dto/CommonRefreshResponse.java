package com.jmna.auth.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
public class CommonRefreshResponse extends CommonResponse {
    private String accessToken;

    @Builder
    CommonRefreshResponse(String message, String accessToken) {
        super(message);
        this.accessToken = accessToken;
    }
}
