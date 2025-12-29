package com.jmna.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

@SuperBuilder
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CommonLoginResponse extends CommonRefreshResponse {
    private String refreshToken;
    private String provider;
}
