package com.jmna.auth.handler;

import com.jmna.auth.entity.User;
import com.jmna.auth.service.UserService;
import com.jmna.auth.userdetails.CustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final UserService userService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, UsernameNotFoundException {

        String username = authentication.getName();

        if (!(authentication.getPrincipal() instanceof CustomUserDetails principal)) {
            throw new IllegalStateException("로컬 로그인 principal 타입이 올바르지 않습니다.");
        }

        // 유저를 로그인 처리할 시, Access Token, Refresh Token을 생성하고 저장
        userService.loginUser(principal.getUser().getId(), response);
    }
}
