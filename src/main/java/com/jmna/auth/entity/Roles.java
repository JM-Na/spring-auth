package com.jmna.auth.entity;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

@Getter
public enum Roles implements GrantedAuthority {
    ROLE_ADMIN("관리자"), ROLE_USER("일반 회원");

    private final String description;

    Roles(String description) {
        this.description = description;
    }

    @Override
    public String getAuthority() {
        return name();
    }

}
