package com.jmna.auth.controller;

import com.jmna.auth.dto.InfoUpdateRequest;
import com.jmna.auth.dto.PasswordChangeRequest;
import com.jmna.auth.dto.PasswordCheckRequest;
import com.jmna.auth.dto.SignupRequest;
import com.jmna.auth.service.TokenService;
import com.jmna.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
    public ResponseEntity<?> signup(HttpServletRequest request, @RequestBody SignupRequest dto) {
        log.info("{} {} 회원가입 요청", request.getMethod(), request.getServletPath());
        try {
            userService.registerUser(dto);
            return ResponseEntity.ok("회원가입 완료");
        } catch (IllegalArgumentException e) {
            String result = String.format("{\"message\":\"%s\"}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(result);
        }
    }

    // 로그아웃
    @GetMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        userService.logoutUser(request);
        return ResponseEntity.ok("로그아웃 성공");
    }

    // 회원 탈퇴
    @DeleteMapping("/user")
    public ResponseEntity<?> deleteUser(HttpServletRequest request, @RequestBody PasswordCheckRequest dto) {
        try {
            userService.deleteUser(request, dto);
            return ResponseEntity.ok("{\"message\":\"회원 탈퇴 성공\"}");
        } catch (Exception e) {
            String result = String.format("{\"message\":\"%s\"}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(result);
        }
    }

    // Refresh Token으로 JWT 갱신
    @GetMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request) {
        try {
            String accessToken = tokenService.refreshAccessToken(request);
            String result = String.format("{\"message\":\"토큰 갱신 성공\", \"accessToken\":\"%s\"}", accessToken);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            String result = String.format("{\"message\":\"%s\"}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(result);
        }
    }

    // 비밀 번호 변경
    @PatchMapping("/user/credentials")
    public ResponseEntity<?> updateCredentials(HttpServletRequest request, @RequestBody PasswordChangeRequest dto) {
        try {
            userService.changePassword(request, dto);
            return ResponseEntity.ok("{\"message\":\"비밀번호 변경 성공\"}");
        } catch (Exception e) {
            String result = String.format("{\"message\":\"%s\"}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(result);
        }
    }

    // 회원 정보 변경
    @PatchMapping("/user")
    public ResponseEntity<?> updateUser(HttpServletRequest request, @RequestBody InfoUpdateRequest dto) {
        try {
            userService.changeUserInfo(request, dto);
            return ResponseEntity.ok("{\"message\":\"회원정보 변경 성공\"}");
        } catch (Exception e) {
            String result = String.format("{\"message\":\"%s\"}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(result);
        }
    }

    // 비밀 번호 검증
    @PostMapping("/check")
    public ResponseEntity<?> check(HttpServletRequest request, @RequestBody PasswordCheckRequest dto) {
        Boolean matches = userService.checkPassword(request, dto);
        String result = String.format("{\"message\":\"비밀번호 검증 결과\", \"matches\":\"%s\"}", matches);
        return ResponseEntity.ok(result);
    }
}
