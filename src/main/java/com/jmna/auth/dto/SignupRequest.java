package com.jmna.auth.dto;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class SignupRequest {
    private String username;
    private String password;
}
