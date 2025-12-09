package com.jmna.auth.service;

import com.jmna.auth.entity.RefreshToken;
import com.jmna.auth.entity.User;
import com.jmna.auth.jwt.JwtTokenProvider;
import com.jmna.auth.repository.RefreshTokenRepository;
import com.jmna.auth.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {
    private final UserRepository userRepository;
    private final RefreshTokenRepository tokenRepository;
    private final JwtTokenProvider tokenProvider;

    // 유저 이름으로 토큰 검색
    public RefreshToken findUserRefreshToken(String username) {
        User user = userRepository.findByUsername(username).orElseThrow();
        return user.getRefreshToken();
    }

    // RefreshToken 검증
    public Boolean verifyRefreshToken(String tokenValue) {
        String username = tokenProvider.getUsername(tokenValue);
        RefreshToken refreshToken = findUserRefreshToken(username);
        return refreshToken.getTokenValue().equals(tokenValue);
    }



    public String getTokenUsername(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.startsWith("Bearer ")) {
            String jwt = authorization.substring(7);
            return tokenProvider.getUsername(jwt);
        } else {
            throw new AuthenticationCredentialsNotFoundException("");
        }
    }

    // 로그아웃 시 해당 유저의 Refresh Token을 DB에서 삭제
    public void deleteUserToken(User user) {
        RefreshToken refreshToken = user.getRefreshToken();
        user.setToken(null);
        deleteRefreshToken(refreshToken);
    }

    // RefreshToken 삭제
    private void deleteRefreshToken(RefreshToken refreshToken) {
        tokenRepository.delete(refreshToken);
    }

    // Refresh Token으로 Access Token 갱신
    public String refreshAccessToken(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.startsWith("Bearer ")) {
            String jwt = authorization.substring(7);
            String username = tokenProvider.getUsername(jwt);
            if (verifyRefreshToken(jwt))
                return tokenProvider.generateAccessToken(username);
            else
                throw new BadCredentialsException("Refresh Token 검증에 실패했습니다.");
        }
        else {
            throw new AuthenticationCredentialsNotFoundException("Invalid or missing JWT");
        }
    }

    public void saveRefreshToken(RefreshToken token) {
        tokenRepository.save(token);
    }
}
