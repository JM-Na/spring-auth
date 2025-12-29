package com.jmna.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jmna.auth.dto.CommonLoginResponse;
import com.jmna.auth.dto.LoginRequest;
import com.jmna.auth.dto.SignupRequest;
import com.jmna.auth.jwt.JwtTokenProvider;
import com.jmna.auth.service.UserService;
import jakarta.servlet.ServletException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.IOException;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@SpringBootTest
@AutoConfigureMockMvc
class CustomJwtAuthenticationFilterTest {

    @Autowired
    MockMvc mockMvc;
    @Autowired
    JwtTokenProvider tokenProvider;
    @Autowired
    UserService userService;

    CustomJwtAuthenticationFilter jwtFilter;
    MockHttpServletRequest mockRequest;
    MockHttpServletResponse mockResponse;
    MockFilterChain mockFilterChain;

    @BeforeEach
    void setup() {
        mockRequest = new MockHttpServletRequest();
        mockResponse = new MockHttpServletResponse();
        mockFilterChain = new MockFilterChain();
        jwtFilter = new CustomJwtAuthenticationFilter(tokenProvider);
    }

    @Test
    void JWT검사_대상아님() throws ServletException, IOException {
        mockRequest.setServletPath("/auth/login");
        jwtFilter.doFilter(mockRequest, mockResponse, mockFilterChain);

        Assertions.assertThat(mockResponse.getStatus()).isEqualTo(200);
    }

    @Test
    void 헤더가_없음() throws ServletException, IOException {
        mockRequest.setServletPath("/auth/test");
        jwtFilter.doFilter(mockRequest, mockResponse, mockFilterChain);

        Assertions.assertThat(mockResponse.getStatus())
                .isEqualTo(401);
        Assertions.assertThat(mockResponse.getContentAsString())
                .isEqualTo("Authorization 헤더가 존재하지 않거나 유효하지 않은 형태의 헤더값입니다.");
    }

    @Test
    void JWT가_없음() throws ServletException, IOException {
        mockRequest.setServletPath("/auth/test");
        mockRequest.addHeader("Authorization", " ");
        jwtFilter.doFilter(mockRequest, mockResponse, mockFilterChain);

        Assertions.assertThat(mockResponse.getStatus())
                .isEqualTo(401);
        Assertions.assertThat(mockResponse.getContentAsString())
                .isEqualTo("Authorization 헤더가 존재하지 않거나 유효하지 않은 형태의 헤더값입니다.");
    }

    @Test
    void JWT가_유효하지_않음() throws ServletException, IOException {
        mockRequest.setServletPath("/auth/test");
        mockRequest.addHeader("Authorization", "Bearer  ");
        jwtFilter.doFilter(mockRequest, mockResponse, mockFilterChain);

        Assertions.assertThat(mockResponse.getStatus())
                .isEqualTo(401);
        Assertions.assertThat(mockResponse.getContentAsString())
                .isEqualTo("JWT가 유효하지 않거나 존재하지 않습니다.");
    }

    @Test
    void JWT_인증_성공() throws Exception {
        // 테스트 유저 회원 가입
        SignupRequest dto = SignupRequest.builder()
                .username("test")
                .password("test")
                .build();

        userService.registerUser(dto);
        
        // 테스트 유저 로그인 후 토큰 생성
        LoginRequest req = new LoginRequest("test","test");

        MvcResult mvcResult = mockMvc.perform(
                post("/auth/login")
                        .servletPath("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(req))
        ).andReturn();

        MockHttpServletResponse response = mvcResult.getResponse();
        CommonLoginResponse loginResponse = new ObjectMapper().readValue(response.getContentAsString(), CommonLoginResponse.class);
        String accessToken = loginResponse.getAccessToken();

        // JWT를 포함한 요청 생성
        mockRequest.setServletPath("/auth/test");
        mockRequest.addHeader("Authorization", "Bearer " + accessToken);

        jwtFilter.doFilter(mockRequest, mockResponse, mockFilterChain);

        Assertions.assertThat(mockResponse.getStatus()).isEqualTo(200);
    }
}