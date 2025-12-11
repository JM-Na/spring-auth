package com.jmna.auth.jwt;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * JWT 토큰 설정
 */
@Configuration
public class TokenConfig {

    private StoredRSAKey currentKey;
    private final List<StoredRSAKey> previousKeys = new ArrayList<>();

    private static final Duration RETENTION_PERIOD = Duration.ofDays(7); // TODO 이걸 @Value로 바꿀수는 없을지?

    public TokenConfig() {
        this.currentKey = new StoredRSAKey(generateRSAKey());
    }

    public JWKSet getJWKSet() {
        List<JWK> keys = new ArrayList<>();
        keys.add(currentKey.getRsaKey());
        previousKeys.forEach(storedKey -> keys.add(storedKey.getRsaKey()));
        return new JWKSet(keys);
    }

    @Scheduled(cron = "0 0 0 * * ?")
    public synchronized void rotate() {
        previousKeys.add(currentKey);

        currentKey = new StoredRSAKey(generateRSAKey());

        Instant now = Instant.now();
        previousKeys.removeIf(storedKey ->
                storedKey.getCreatedAt().plus(RETENTION_PERIOD).isBefore(now));
    }

    // RSAKey 생성
    public RSAKey generateRSAKey() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();

            return new RSAKey
                    .Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(UUID.randomUUID().toString())
                    .build();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // 서명 키 JWK 집합
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        return ((jwkSelector, securityContext) -> jwkSelector.select(getJWKSet()));
    }

    // 토큰 발급 시 서명
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    // 토큰 검증용 디코더
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    // 토큰 발급 시 클레임 커스터마이징
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> context.getClaims().claim("", "");
    }
}
