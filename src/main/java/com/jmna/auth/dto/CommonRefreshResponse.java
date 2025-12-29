package com.jmna.auth.dto;

import lombok.Getter;
import lombok.experimental.SuperBuilder;

@SuperBuilder
@Getter
public class CommonRefreshResponse extends CommonResponse {
    private String accessToken;
}
