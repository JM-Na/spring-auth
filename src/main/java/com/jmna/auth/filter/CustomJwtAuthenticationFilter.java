package com.jmna.auth.filter;

import com.jmna.auth.jwt.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomJwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider tokenProvider;

    private static final List<String> EXCLUDED_PATHS = List.of(
            "/", "/auth/login", "/auth/signup", "/auth/refresh"
    );

    // 로그인 또는 회원가입에 대해서는 JWT 검사를 하지 않음.
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return EXCLUDED_PATHS.contains(path) || path.contains("oauth2");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("{}: JWT 인증이 필요한 요청이 발생했습니다.", request.getServletPath());

        String authorization = request.getHeader("Authorization");

        // JWT가 없는 경우, 인증을 생략하고 다음 필터로 넘김 -> authenticated()가 적용된 엔드포인트는 자동으로 거부됨
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            log.info("Authorization 헤더가 존재하지 않거나 유효하지 않은 형태의 헤더값입니다.");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("text/html;charset=UTF-8");
            response.getWriter().write("Authorization 헤더가 존재하지 않거나 유효하지 않은 형태의 헤더값입니다.");
            filterChain.doFilter(request, response);
            return;
        }

        String jwt = authorization.substring(7);

        try {
            if (tokenProvider.verify(jwt)) {
                log.info("Access Token 인증 성공");
                Authentication authentication = tokenProvider.getAuthentication(jwt);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            log.warn("JWT가 유효하지 않거나 존재하지 않습니다.");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("text/html;charset=UTF-8");
            response.getWriter().write("JWT가 유효하지 않거나 존재하지 않습니다.");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
