package com.jmna.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jmna.auth.dto.LoginRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
public class CustomLoginAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // 로그인 요청에만 해당 필터가 작동
    public CustomLoginAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
        setRequiresAuthenticationRequestMatcher(
                PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/auth/login")
        );
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        try {
            // JSON Body 읽기
            ObjectMapper mapper = new ObjectMapper();
            LoginRequest loginRequest = mapper.readValue(request.getInputStream(), LoginRequest.class);
            String username = loginRequest.getUsername();
            String password = loginRequest.getPassword();
            if (username == null || password == null) {
                throw new BadCredentialsException("Username or Password missing");
            }
            // Body에서 얻은 정보로 UsernamePasswordAuthenticationToken 생성
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
            setDetails(request, authRequest);

            // AuthenticationManager → UserDetailsService → PasswordEncoder 흐름으로 진행됨
            return this.getAuthenticationManager().authenticate(authRequest);

        } catch (IOException e) {
            System.out.println("e = " + e);
            throw new AuthenticationServiceException("Invalid login request format");
        }
    }
}
