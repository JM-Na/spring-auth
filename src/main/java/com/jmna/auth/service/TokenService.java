package com.jmna.auth.service;

import com.jmna.auth.entity.RefreshToken;
import com.jmna.auth.entity.User;
import com.jmna.auth.exception.InvalidJWTException;
import com.jmna.auth.jwt.JwtTokenProvider;
import com.jmna.auth.jwt.TokenType;
import com.jmna.auth.repository.RefreshTokenRepository;
import com.jmna.auth.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {
    private final UserRepository userRepository;
    private final RefreshTokenRepository tokenRepository;
    private final JwtTokenProvider tokenProvider;

    public RefreshToken findUserRefreshToken(Long userId) {
        User user = userRepository.findById(userId).orElseThrow(
                InvalidJWTException::new
        );

        RefreshToken refreshToken = user.getRefreshToken();

        if (refreshToken == null)
            throw new InvalidJWTException();

        return refreshToken;
    }

    // RefreshToken 검증
    public Boolean verifyRefreshToken(String tokenValue) {
        Long userId = tokenProvider.getUserId(tokenValue);
        RefreshToken refreshToken = findUserRefreshToken(userId);
        return refreshToken.getTokenValue().equals(tokenValue);
    }

    public Long getTokenUserId(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.startsWith("Bearer ")) {
            String jwt = authorization.substring(7);
            return tokenProvider.getUserId(jwt);
        } else {
            log.error("JWT 정보 추출 실패: Authorization 헤더가 존재하지 않거나 그 값의 형식이 잘못되었습니다.");
            throw new InvalidJWTException();
        }
    }

    // 로그아웃 시 해당 유저의 Refresh Token을 DB에서 삭제
    public void deleteUserToken(User user) {
        String username = user.getUsername();
        RefreshToken refreshToken = user.getRefreshToken();
        user.setToken(null);
        tokenRepository.delete(refreshToken);
        log.info("Refresh Token 삭제 성공, 사용자명: {}", username);
    }

    // Refresh Token으로 Access Token 갱신
    public String refreshAccessToken(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.startsWith("Bearer ")) {
            String givenRefreshToken = authorization.substring(7);
            Long userId = tokenProvider.getUserId(givenRefreshToken);
            if (verifyRefreshToken(givenRefreshToken)) {
                log.info("Refresh Token 검증 성공, 사용자명: {}", userId);
                return tokenProvider.generateToken(userId, TokenType.ACCESS);
            } else {
                log.error("Refresh Token 검증 실패, 사용자명: {}", userId);
                throw new InvalidJWTException();
            }
        } else {
            log.error("Refresh Token 검증 실패: Authorization 헤더가 존재하지 않거나 그 값의 형식이 잘못되었습니다.");
            throw new InvalidJWTException();
        }
    }

    public void saveRefreshToken(RefreshToken token) {
        tokenRepository.save(token);
    }
}
