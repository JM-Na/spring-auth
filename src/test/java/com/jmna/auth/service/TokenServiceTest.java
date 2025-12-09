package com.jmna.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jmna.auth.dto.LoginRequest;
import com.jmna.auth.dto.LoginResponse;
import com.jmna.auth.dto.SignupRequest;
import com.jmna.auth.entity.RefreshToken;
import com.jmna.auth.entity.User;
import com.jmna.auth.jwt.JwtTokenProvider;
import com.jmna.auth.repository.RefreshTokenRepository;
import com.jmna.auth.repository.UserRepository;
import jakarta.persistence.EntityManager;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.jwt.Jwt;
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
class TokenServiceTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    EntityManager em;

    @Autowired
    private UserService userService;
    @Autowired
    private TokenService tokenService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RefreshTokenRepository tokenRepository;
    @Autowired
    private JwtTokenProvider tokenProvider;

    String accessToken;
    String refreshToken;
    MockHttpServletRequest mockHttpServletRequest;

    @BeforeEach
    void 회원가입_후_로그인() throws Exception {
        SignupRequest dto = SignupRequest.builder()
                .username("test")
                .password("test")
                .build();

        userService.registerUser(dto);

        LoginRequest req = new LoginRequest("test","test");

        MvcResult mvcResult = mockMvc.perform(
                post("/auth/login")
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

    @Test
    void findUserRefreshToken() {
        RefreshToken userRefreshToken = tokenService.findUserRefreshToken("test");

        Assertions.assertThat(userRefreshToken).isEqualTo(userRepository.findByUsername("test").get().getRefreshToken());
    }

    @Test
    void verifyRefreshToken() {
        Assertions.assertThat(tokenService.verifyRefreshToken(refreshToken)).isTrue();
    }


    @Test
    void getTokenUsername() {
        String tokenUsername = tokenService.getTokenUsername(mockHttpServletRequest);

        Assertions.assertThat(tokenUsername).isEqualTo("test");
    }

    @Test
    void deleteUserToken() {
        User user = userRepository.findByUsername("test").orElseThrow();
        tokenService.deleteUserToken(user);
        Assertions.assertThatThrownBy(() ->  tokenRepository.findByTokenValue(refreshToken).orElseThrow())
                .isInstanceOf(NoSuchElementException.class);
        Assertions.assertThat(user.getRefreshToken()).isNull();
    }

    @Test
    void refreshAccessToken() {
        MockHttpServletRequest mockRefreshRequest = new MockHttpServletRequest();
        mockRefreshRequest.addHeader("Authorization", "Bearer " + refreshToken);

        String newAccessToken = tokenService.refreshAccessToken(mockRefreshRequest);
        Jwt jwt = tokenProvider.decode(newAccessToken);
        String type = jwt.getClaim("type");

        Assertions.assertThat(type).isEqualTo("access");
        Assertions.assertThat(tokenProvider.verify(newAccessToken)).isTrue();

    }

}