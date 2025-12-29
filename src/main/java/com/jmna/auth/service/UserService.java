package com.jmna.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jmna.auth.dto.*;
import com.jmna.auth.entity.RefreshToken;
import com.jmna.auth.entity.Roles;
import com.jmna.auth.entity.User;
import com.jmna.auth.exception.InvalidUsernameException;
import com.jmna.auth.jwt.JwtTokenProvider;
import com.jmna.auth.oauth.CustomOAuth2User;
import com.jmna.auth.repository.UserRepository;
import com.jmna.auth.userdetails.SecurityUtils;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final JwtTokenProvider tokenProvider;

    public void registerUser(SignupRequest dto) {
        if (userRepository.findByUsername(dto.getUsername()).isPresent()) {
            log.error("회원가입 오류: 동일한 사용자명이 이미 존재합니다.");
            throw new IllegalArgumentException("동일한 사용자명이 이미 존재합니다.");
        }
        if (Objects.equals(dto.getUsername(), "") || Objects.equals(dto.getPassword(), "")) {
            log.error("회원가입 오류: 사용자명 또는 비밀번호가 입력되지 않았습니다.");
            throw new IllegalArgumentException("사용자명 또는 비밀번호가 입력되지 않았습니다.");
        }
        User user = User.builder()
                .username(dto.getUsername())
                .password(passwordEncoder.encode(dto.getPassword()))
                .provider("local")
                .roles(List.of(Roles.ROLE_USER))
                .build();
        userRepository.save(user);
        log.info("회원가입 성공, 사용자명: {}", dto.getUsername());
    }

    @PreAuthorize("#dto.username == principal.user.username")
    public void deleteUser(PasswordCheckRequest dto) throws AccessDeniedException {
        User user = SecurityUtils.getCurrentUser();
        if (passwordEncoder.matches(dto.getPassword(), user.getPassword())) {
            userRepository.delete(user);
            log.info("회원탈퇴 성공, 사용자명: {}", user.getUsername());
        } else {
            log.error("회원탈퇴 오류: 비밀번호 확인에 실패했습니다.");
            throw new BadCredentialsException("잘못된 정보입니다. 다시 입력해주세요.");
        }
    }

    @PreAuthorize("#dto.username == principal.user.username")
    public void changePassword(PasswordChangeRequest dto) throws AccessDeniedException {
        User user = SecurityUtils.getCurrentUser();
        if (passwordEncoder.matches(dto.getCurrentPassword(), user.getPassword())) {
            user.updatePassword(passwordEncoder.encode(dto.getNewPassword()));
            userRepository.save(user);
            log.info("비밀번호 변경 성공, 사용자명: {}", user.getUsername());
        } else {
            log.error("비밀번호 변경 오류: 비밀번호 확인에 실패했습니다.");
            throw new BadCredentialsException("잘못된 정보입니다. 다시 입력해주세요.");
        }
    }

    @PreAuthorize("#dto.username == principal.user.username")
    public void changeUserInfo(InfoUpdateRequest dto) throws AccessDeniedException {
        User user = SecurityUtils.getCurrentUser();
        if (userRepository.findByUsername(dto.getUsername()).isPresent()) {
            log.error("사용자 정보 변경 오류: 동일한 사용자명이 이미 존재합니다.");
            throw new InvalidUsernameException();
        }
        user.updateDetails(dto);
        userRepository.save(user);
        log.info("사용자 정보 변경 성공: {}", user.getUsername());
    }

    @PreAuthorize("#dto.username == principal.user.username")
    public Boolean checkPassword(PasswordCheckRequest dto) throws AccessDeniedException {
        User user = SecurityUtils.getCurrentUser();
        return passwordEncoder.matches(dto.getPassword(), user.getPassword());
    }

    // 일반 유저 로그인 처리
    public void loginUser(String username, HttpServletResponse response) throws IOException {
        // JWT 생성
        String accessToken = tokenProvider.generateAccessToken(username);
        String refreshToken = tokenProvider.generateRefreshToken(username);

        User user = userRepository.findByUsername(username).orElseThrow();

        saveUserAndToken(refreshToken, user);

        setLoginResponse(response, "로그인에 성공했습니다.", accessToken, refreshToken, "local");
    }

    // OAuth2 유저 로그인 처리
    public void loginUser(CustomOAuth2User oAuth2User, HttpServletResponse response) throws IOException {

        String username = oAuth2User.getName();
        String provider = oAuth2User.getProvider();

        // JWT 생성
        String accessToken = tokenProvider.generateAccessToken(username);
        String refreshToken = tokenProvider.generateRefreshToken(username);

        try {
            User user = userRepository.findByUsername(username).orElseThrow();
            saveUserAndToken(refreshToken, user);

            setLoginResponse(response, "로그인에 성공했습니다.", accessToken, refreshToken, provider);
        } catch (NoSuchElementException e) {
            log.info("{}: 해당 유저가 DB 내에 존재하지 않습니다.", e.getMessage());

            User user = User.builder()
                    .username(username)
                    .password(null)
                    .provider(provider)
                    .roles(List.of(Roles.ROLE_USER))
                    .build();

            saveUserAndToken(refreshToken, user);

            setLoginResponse(response, "회원가입 및 로그인에 성공했습니다.", accessToken, refreshToken, provider);
        }
    }

    @PreAuthorize("#dto.username == principal.user.username")
    public void logoutUser(LogoutRequest dto) throws AccessDeniedException {
        User user = SecurityUtils.getCurrentUser();
        tokenService.deleteUserToken(user);
        log.info("로그아웃 성공: {}", user.getUsername());
    }

    // 응답 JSON 생성
    private void setLoginResponse(HttpServletResponse response, String message,
                                  String accessToken, String refreshToken, String provider) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json;charset=UTF-8");

        CommonLoginResponse loginResponse = CommonLoginResponse.builder()
                .message(message)
                .provider(provider)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();

        response.getWriter().write(objectMapper.writeValueAsString(loginResponse));
    }

    //  RefreshToken 저장 (DB/TODO Redis)
    // 토큰, 유저 생성 및 저장
    private void saveUserAndToken(String refreshToken, User user) {
        userRepository.save(user);
        RefreshToken token = new RefreshToken(refreshToken, user);
        user.setToken(token);
        tokenService.saveRefreshToken(token);
        userRepository.save(user);
    }
}
