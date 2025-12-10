package com.jmna.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jmna.auth.dto.LoginRequest;
import com.jmna.auth.dto.SignupRequest;
import com.jmna.auth.service.UserService;
import jakarta.servlet.ServletException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;

import java.io.IOException;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(MockitoExtension.class)
class CustomLoginAuthenticationFilterTest {

    @Autowired
    UserService userService;

    CustomLoginAuthenticationFilter loginFilter;
    MockHttpServletRequest mockRequest;
    MockHttpServletResponse mockResponse;
    MockFilterChain mockFilterChain;

    @BeforeAll
    void beforeAll() {
        SignupRequest dto = SignupRequest.builder()
                .username("test")
                .password("test")
                .build();

        userService.registerUser(dto);
    }

    @BeforeEach
    void beforeEach() {
        mockRequest = new MockHttpServletRequest();
        mockResponse = new MockHttpServletResponse();
        mockFilterChain = new MockFilterChain();
        AuthenticationManager am = Mockito.mock(AuthenticationManager.class);
        loginFilter = new CustomLoginAuthenticationFilter(am);

        mockRequest.setMethod("POST");
        mockRequest.setRequestURI("/auth/login");
        mockRequest.setServletPath("/auth/login");
    }

    @Test
    void 필터대상_아님() throws ServletException, IOException {
        mockRequest.setServletPath("/auth/test");
        loginFilter.doFilter(mockRequest, mockResponse, mockFilterChain);

        Boolean isExecuted = (Boolean) mockRequest.getAttribute("LOGIN_FILTER_EXECUTED");

        Assertions.assertThat(isExecuted).isNull();
    }

    @Test
    void 로그인_형식_오류() throws Exception {
        String req = "this is test string";

        mockRequest.setContentType("text/html;UTF-8");
        mockRequest.setContent(new ObjectMapper().writeValueAsString(req).getBytes());

        loginFilter.doFilter(mockRequest, mockResponse, mockFilterChain);

        Boolean isExecuted = (Boolean) mockRequest.getAttribute("LOGIN_FILTER_EXECUTED");

        Assertions.assertThat(mockResponse.getStatus()).isEqualTo(401);
        Assertions.assertThat(isExecuted).isNull();
    }

    @Test
    void 특정_필드값_없음() throws IOException, ServletException {
        LoginRequest req = new LoginRequest("test", " ");

        mockRequest.setContent(new ObjectMapper().writeValueAsString(req).getBytes());

        loginFilter.doFilter(mockRequest, mockResponse, mockFilterChain);

        Boolean isExecuted = (Boolean) mockRequest.getAttribute("LOGIN_FILTER_EXECUTED");

        Assertions.assertThat(mockResponse.getStatus()).isEqualTo(401);
        Assertions.assertThat(isExecuted).isNull();
    }

    @Test
    void 로그인_성공() throws ServletException, IOException {
        LoginRequest req = new LoginRequest("test", "test");

        mockRequest.setContent(new ObjectMapper().writeValueAsString(req).getBytes());

        loginFilter.doFilter(mockRequest, mockResponse, mockFilterChain);

        Boolean isExecuted = (Boolean) mockRequest.getAttribute("LOGIN_FILTER_EXECUTED");

        Assertions.assertThat(mockResponse.getStatus()).isEqualTo(200);
        Assertions.assertThat(isExecuted).isTrue();
    }


}