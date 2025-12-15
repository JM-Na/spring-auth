package com.jmna.auth.jwt;

import com.jmna.auth.exception.InvalidJWTException;
import com.jmna.auth.userdetails.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

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


    // Access Token 생성
    public String generateAccessToken(String username) {
        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("jmna-auth-server")
                .issuedAt(now)
                .expiresAt(now.plus(ACCESS_TOKEN_EXPIRE_MIN, ChronoUnit.MINUTES))
                .subject(username)
                .claim("type", "access")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    // Refresh Token 생성
    public String generateRefreshToken(String username) {
        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("jmna-auth-server")
                .issuedAt(now)
                .expiresAt(now.plus(REFRESH_TOKEN_EXPIRE_DAY, ChronoUnit.DAYS))
                .subject(username)
                .claim("type", "refresh")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    // JWT 토큰 검증
    public Jwt decode(String token) {
        return jwtDecoder.decode(token);
    }

    // 토론에서 username 추출
    public String getUsername(String token) {
        return jwtDecoder.decode(token).getSubject();
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
            if (!type.equals("access"))
                return false;
        } catch (JwtException e) {
            throw new InvalidJWTException();
        }
        return true;
    }

    public Authentication getAuthentication(String token) {
        String username = getUsername(token);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
    }
}
