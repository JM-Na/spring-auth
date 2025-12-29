package com.jmna.auth.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class PasswordCheckRequest {
    private String username;
    private String password;
}
