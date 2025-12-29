package com.jmna.auth.controller;

import com.jmna.auth.dto.*;
import com.jmna.auth.service.TokenService;
import com.jmna.auth.service.UserService;
import com.jmna.auth.userdetails.CustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final UserService userService;
    private final TokenService tokenService;

    // 회원가입
    @PostMapping("/signup")
    public CommonResponse signup(@RequestBody SignupRequest dto) {
        userService.registerUser(dto);
        return CommonResponse.builder()
                .message("회원가입 성공")
                .build();
    }

    // 로그아웃
    @GetMapping("/logout")
    public CommonResponse logout(@AuthenticationPrincipal CustomUserDetails userDetails) {
        userService.logoutUser(userDetails);
        return CommonResponse.builder()
                .message("로그아웃 성공")
                .build();
    }

    // 회원 탈퇴
    @DeleteMapping("/user")
    public CommonResponse deleteUser(@AuthenticationPrincipal CustomUserDetails userDetails, @RequestBody PasswordCheckRequest dto) {
        userService.deleteUser(userDetails, dto);
        return CommonResponse.builder()
                .message("회원 탈퇴 성공")
                .build();
    }

    // Refresh Token으로 JWT 갱신
    @GetMapping("/refresh")
    public CommonResponse refresh(HttpServletRequest request) {
        return CommonRefreshResponse.builder()
                .message("토큰 갱신 성공")
                .accessToken(tokenService.refreshAccessToken(request))
                .build();
    }

    // 비밀 번호 변경
    @PatchMapping("/user/credentials")
    public CommonResponse updateCredentials(@AuthenticationPrincipal CustomUserDetails userDetails, @RequestBody PasswordChangeRequest dto) {
        userService.changePassword(userDetails, dto);
        return CommonResponse.builder()
                .message("비밀번호 변경 성공")
                .build();
    }

    // 회원 정보 변경
    @PatchMapping("/user")
    public CommonResponse updateUser(@AuthenticationPrincipal CustomUserDetails userDetails, @RequestBody InfoUpdateRequest dto) {
        userService.changeUserInfo(userDetails, dto);
        return CommonResponse.builder()
                .message("회원정보 변경 성공")
                .build();
    }

    // 비밀 번호 검증
    @PostMapping("/check")
    public CommonResponse check(@AuthenticationPrincipal CustomUserDetails userDetails, @RequestBody PasswordCheckRequest dto) {
        Boolean matches = userService.checkPassword(userDetails, dto);
        return CommonResponse.builder()
                .message("비밀번호 검증 결과: " + matches.toString())
                .build();
    }
}
