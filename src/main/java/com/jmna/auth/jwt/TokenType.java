package com.jmna.auth.jwt;

public enum TokenType {
    ACCESS("access"),
    REFRESH("refresh")
    ;

    TokenType(String claimValue) {
        this.claimValue = claimValue;
    }

    private final String claimValue;

    String claimValue() {
        return this.claimValue;
    }
}
