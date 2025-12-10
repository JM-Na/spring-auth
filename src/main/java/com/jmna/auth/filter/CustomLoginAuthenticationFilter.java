package com.jmna.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jmna.auth.dto.LoginRequest;
import io.micrometer.common.util.StringUtils;
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
import java.sql.Time;
import java.sql.Timestamp;

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
            log.info("로그인 요청이 발생했습니다.");

            // JSON Body 읽기
            ObjectMapper mapper = new ObjectMapper();
            LoginRequest loginRequest = mapper.readValue(request.getInputStream(), LoginRequest.class);

            // Body에서 유저의 정보 추출
            String username = loginRequest.getUsername();
            String password = loginRequest.getPassword();
            if (StringUtils.isBlank(username) || StringUtils.isBlank(password)) {
                log.error("사용자명 또는 비밀번호 값이 존재하지 않습니다.");
                throw new BadCredentialsException("사용자명 또는 비밀번호 값이 존재하지 않습니다.");
            }
            
            // Body에서 얻은 정보로 UsernamePasswordAuthenticationToken 생성
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
            setDetails(request, authRequest);

            // 필터가 작동했다는 사실을 attribute에 기록
            request.setAttribute("LOGIN_FILTER_EXECUTED", true);

            log.info("로그인 성공, 사용자명: {}", username);

            // AuthenticationManager → UserDetailsService → PasswordEncoder 흐름으로 진행됨
            return this.getAuthenticationManager().authenticate(authRequest);

        } catch (IOException e) {
            log.error("올바르지 않은 바디 형식입니다.");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            throw new AuthenticationServiceException("올바르지 않은 바디 형식입니다.");
        }
    }
}
