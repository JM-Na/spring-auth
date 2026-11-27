package com.jmna.auth.controller;

import com.jmna.auth.dto.*;
import com.jmna.auth.service.TokenService;
import com.jmna.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.nio.file.AccessDeniedException;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final UserService userService;
    private final TokenService tokenService;

    // TODO(#8): 5-1.1. email을 EmailService에 넘기고, 응답에는 서비스가 반환한 challengeId를 담는다.
    @PostMapping("/signup/email/send")
    public void sendEmail(@Valid @RequestBody SendEmailRequest dto) {

    }
    // TODO(#8): 5-1.2. challengeId와 verifyCode를 EmailService의 확인 메서드에 넘긴다.
    // 코드 비교가 끝난 뒤 이어지는 단계에서 emailVerificationId 응답을 연결한다.
    // 두 POST 경로는 가입 전 호출하므로 WebSecurityConfig와 JWT 필터의 경로를 함께 확인한다.
    @PostMapping("/signup/email/verify")
    public void verifyEmailCode(@Valid @RequestBody EmailCodeVerifyRequest dto){

    }

    // TODO(#8): 5-1.3. 기존 POST /auth/signup에서 email과 emailVerificationId가 담긴 SignupRequest를 가입 서비스에 넘긴다.
    @PostMapping("/signup")
    public CommonResponse signup(@RequestBody SignupRequest dto) {
        userService.registerUser(dto);
        return CommonResponse.builder()
                .message("회원가입 성공")
                .build();
    }

    // TODO(#8): 5-5. 이메일 확인이나 기존 계정 인증을 마친 뒤 소셜 로그인 대기 요청을 이어가는 경로를 잡는다.
    // requestId로 대기 요청을 확인하고, 기존 계정 연동에서는 인증된 principal의 내부 회원 ID를 서비스에 넘긴다.

    // 로그아웃
    @PostMapping("/logout")
    public CommonResponse logout(@RequestBody LogoutRequest dto) throws AccessDeniedException {
        userService.logoutUser(dto);
        return CommonResponse.builder()
                .message("로그아웃 성공")
                .build();
    }

    // 회원 탈퇴
    @DeleteMapping("/user")
    public CommonResponse deleteUser(@RequestBody PasswordCheckRequest dto) throws AccessDeniedException {
        userService.deleteUser(dto);
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
    public CommonResponse updateCredentials(@RequestBody PasswordChangeRequest dto) throws AccessDeniedException {
        userService.changePassword(dto);
        return CommonResponse.builder()
                .message("비밀번호 변경 성공")
                .build();
    }

    // 회원 정보 변경
    @PatchMapping("/user")
    public CommonResponse updateUser(@RequestBody InfoUpdateRequest dto) throws AccessDeniedException {
        userService.changeUserInfo(dto);
        return CommonResponse.builder()
                .message("회원정보 변경 성공")
                .build();
    }

    // 비밀 번호 검증
    @PostMapping("/check")
    public CommonResponse check(@RequestBody PasswordCheckRequest dto) throws AccessDeniedException {
        Boolean matches = userService.checkPassword(dto);
        return CommonResponse.builder()
                .message("비밀번호 검증 결과: " + matches.toString())
                .build();
    }
}
