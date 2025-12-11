package com.jmna.auth.jwt;

import com.nimbusds.jose.jwk.RSAKey;
import lombok.Getter;

import java.time.Instant;

@Getter
public class StoredRSAKey {
    private final RSAKey rsaKey;
    private final Instant createdAt;

    public StoredRSAKey(RSAKey rsaKey) {
        this.rsaKey = rsaKey;
        this.createdAt = Instant.now();
    }
}
