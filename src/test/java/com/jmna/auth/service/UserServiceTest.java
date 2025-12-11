package com.jmna.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jmna.auth.dto.*;
import com.jmna.auth.entity.User;
import com.jmna.auth.repository.RefreshTokenRepository;
import com.jmna.auth.repository.UserRepository;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.NoSuchElementException;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@Transactional
@AutoConfigureMockMvc
@ActiveProfiles("test")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class UserServiceTest {

    @LocalServerPort
    int port;
    @Autowired
    MockMvc mockMvc;

    @Autowired
    UserService userService;
    @Autowired
    UserRepository userRepository;
    @Autowired
    RefreshTokenRepository tokenRepository;
    @Autowired
    PasswordEncoder passwordEncoder;


    @Test
    void 회원가입_성공() {
        SignupRequest dto = SignupRequest.builder()
                .username("test")
                .password("test")
                .build();

        userService.registerUser(dto);

        Assertions.assertThat(userRepository.findByUsername("test").get()).isNotNull();
    }

    @Test
    void 회원가입_실패() {
        SignupRequest dto = SignupRequest.builder()
                .username("test")
                .password("test")
                .build();

        userService.registerUser(dto);

        Assertions.assertThatThrownBy(() -> userService.registerUser(dto))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("동일한 사용자명이 이미 존재합니다.");

        SignupRequest dto2 = SignupRequest.builder()
                .username("")
                .password("")
                .build();

        Assertions.assertThatThrownBy(() -> userService.registerUser(dto2))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("사용자명 또는 비밀번호가 입력되지 않았습니다.");
    }

    @Test
    void 로컬유저_로그인() throws Exception {
        SignupRequest dto = SignupRequest.builder()
                .username("test")
                .password("test")
                .build();

        userService.registerUser(dto);

        LoginRequest req = new LoginRequest("test", "test");

        mockMvc.perform(
                post("/auth/login")
                        .servletPath("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(req))
        );
    }

    @Test
    void OAuth2유저_로그인() {
    }

    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    @Nested
    class AfterLoginTests {
        String accessToken;
        String refreshToken;
        MockHttpServletRequest mockHttpServletRequest;

        @BeforeAll
        void 회원가입_후_로그인() throws Exception {
            SignupRequest dto = SignupRequest.builder()
                    .username("test")
                    .password("test")
                    .build();

            userService.registerUser(dto);

            LoginRequest req = new LoginRequest("test", "test");

            MvcResult mvcResult = mockMvc.perform(
                    post("/auth/login")
                            .servletPath("/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(new ObjectMapper().writeValueAsString(req))
            ).andReturn();

            MockHttpServletResponse response = mvcResult.getResponse();

            LoginResponse loginResponse = new ObjectMapper().readValue(response.getContentAsString(), LoginResponse.class);

            accessToken = loginResponse.getAccessToken();
            refreshToken = loginResponse.getRefreshToken();

            mockHttpServletRequest = new MockHttpServletRequest();
            mockHttpServletRequest.addHeader("Authorization", "Bearer " + accessToken);
        }

        @Order(1)
        @Test
        void 비밀번호_변경() {
            PasswordChangeRequest dto = PasswordChangeRequest.builder()
                    .currentPassword("test")
                    .newPassword("test1")
                    .build();

            userService.changePassword(mockHttpServletRequest, dto);
            User user = userRepository.findByUsername("test").orElseThrow();
            String password = user.getPassword();
            Assertions.assertThat(passwordEncoder.matches("test1", password)).isTrue();
        }

        @Order(2)
        @Test
        void 회원_정보_변경() {
            InfoUpdateRequest dto = InfoUpdateRequest.builder()
                    .username("testtest")
                    .build();

            userService.changeUserInfo(mockHttpServletRequest, dto);

            Assertions.assertThatThrownBy(() -> userRepository.findByUsername("test").orElseThrow())
                    .isInstanceOf(NoSuchElementException.class);

            Assertions.assertThat(userRepository.findAll().get(0).getUsername()).isEqualTo("testtest");
        }

        @Order(3)
        @Test
        void 비밀번호_확인() {
            PasswordCheckRequest dto = PasswordCheckRequest.builder()
                    .password("test")
                    .build();

            Assertions.assertThat(userService.checkPassword(mockHttpServletRequest, dto)).isTrue();
        }

        @Order(4)
        @Test
        void 회원_탈퇴() {
            PasswordCheckRequest dto = PasswordCheckRequest.builder()
                    .password("test")
                    .build();

            userService.deleteUser(mockHttpServletRequest, dto);

            Assertions.assertThatThrownBy(() -> userRepository.findByUsername("test").orElseThrow())
                    .isInstanceOf(NoSuchElementException.class);
            Assertions.assertThatThrownBy(() -> tokenRepository.findByTokenValue(refreshToken).orElseThrow())
                    .isInstanceOf(NoSuchElementException.class);
        }
    }
}