package com.jmna.auth.dto;

import lombok.Getter;
import lombok.experimental.SuperBuilder;

@SuperBuilder
@Getter
public class CommonLoginResponse extends CommonRefreshResponse {
    private String refreshToken;
    private String provider;
}
