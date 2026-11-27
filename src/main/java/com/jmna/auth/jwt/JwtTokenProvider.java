package com.jmna.auth.jwt;

import com.jmna.auth.exception.InvalidJWTException;
import com.jmna.auth.userdetails.CustomUserDetails;
import com.jmna.auth.userdetails.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import javax.naming.directory.InvalidAttributesException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {
    private final CustomUserDetailsService userDetailsService;
    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;

    // AccessToken 만료 -> 15분
    @Value("${expire.access}")
    private Long ACCESS_TOKEN_EXPIRE_MIN;
    // RefreshToken 만료 -> 7일
    @Value("${expire.refresh}")
    private Long REFRESH_TOKEN_EXPIRE_DAY;


    // Token 생성
    public String generateToken(Long userId, TokenType type) {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt;

        switch (type) {
            case TokenType.ACCESS -> expiresAt = expiresAt.plus(ACCESS_TOKEN_EXPIRE_MIN, ChronoUnit.MINUTES);
            case TokenType.REFRESH -> expiresAt = expiresAt.plus(REFRESH_TOKEN_EXPIRE_DAY, ChronoUnit.DAYS);
        }

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("jmna-auth-server")
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .subject(String.valueOf(userId))
                .claim("type", type.claimValue())
                .claim("subInfo", "userId")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    // JWT 토큰 검증
    public Jwt decode(String token) {
        return jwtDecoder.decode(token);
    }

    public Long getUserId(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);

            Object subInfo = jwt.getClaim("subInfo");

            if ("userId".equals(subInfo)) {
                return Long.valueOf(jwt.getSubject());
            } else {
                throw new InvalidJWTException();
            }
        } catch (JwtException | NumberFormatException e) {
            throw new InvalidJWTException();
        }

    }


    // claim 꺼내기
    public Map<String, Object> getClaims(String token) {
        return jwtDecoder.decode(token).getClaims();
    }

    // Access Token 유효성 검사
    public boolean verify(String token) {
        try {
            // 1. 서명, 유효 기간 검증
            Jwt jwt = decode(token);
            String type = jwt.getClaim("type");
            // 2. 토큰 타입 확인
            if (!type.equals(TokenType.ACCESS.claimValue()))
                return false;
        } catch (JwtException e) {
            throw new InvalidJWTException();
        }
        return true;
    }

    public Authentication getAuthentication(String token) {
        Long userId = getUserId(token);
        CustomUserDetails userDetails = (CustomUserDetails) userDetailsService.loadUserById(userId);
        return new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
    }
}
