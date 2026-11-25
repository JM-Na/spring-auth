package com.jmna.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jmna.auth.dto.CommonLoginResponse;
import com.jmna.auth.dto.InfoUpdateRequest;
import com.jmna.auth.dto.LoginRequest;
import com.jmna.auth.dto.SignupRequest;
import com.jmna.auth.entity.RefreshToken;
import com.jmna.auth.entity.User;
import com.jmna.auth.exception.InvalidJWTException;
import com.jmna.auth.jwt.JwtTokenProvider;
import com.jmna.auth.jwt.TokenType;
import com.jmna.auth.oauth.CustomOAuth2User;
import com.jmna.auth.repository.RefreshTokenRepository;
import com.jmna.auth.repository.UserRepository;
import com.jmna.auth.userdetails.CustomUserDetails;
import com.nimbusds.oauth2.sdk.token.AccessToken;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@Transactional
@AutoConfigureMockMvc
@ActiveProfiles("test")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TokenServiceTest {

    @Autowired
    MockMvc mockMvc;
    @Autowired
    EntityManager em;

    @Autowired
    UserService userService;
    @Autowired
    TokenService tokenService;
    @Autowired
    UserRepository userRepository;
    @Autowired
    RefreshTokenRepository tokenRepository;
    @Autowired
    JwtTokenProvider tokenProvider;
    @Autowired
    JwtEncoder jwtEncoder;

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

        LoginRequest req = new LoginRequest("test", "test");

        MvcResult mvcResult = mockMvc.perform(
                post("/auth/login")
                        .servletPath("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(req))
        ).andReturn();

        MockHttpServletResponse response = mvcResult.getResponse();

        CommonLoginResponse loginResponse = new ObjectMapper().readValue(response.getContentAsString(), CommonLoginResponse.class);

        accessToken = loginResponse.getAccessToken();
        refreshToken = loginResponse.getRefreshToken();

        mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.addHeader("Authorization", "Bearer " + accessToken);
    }

    @Test
    void localLoginTokensContainUserId() {
        User user = userRepository.findByUsername("test").get();
        Long expectedUserId = user.getId();

        Assertions.assertThat(tokenProvider.decode(accessToken).getSubject()).isEqualTo(String.valueOf(expectedUserId));
        Assertions.assertThat(tokenProvider.decode(refreshToken).getSubject()).isEqualTo(String.valueOf(expectedUserId));
    }

    @Test
    void oauth2LoginTokensContainUserId() throws IOException {
        DefaultOAuth2User defaultOAuth2User = new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                Map.of("id", "oauth-test-user"),
                "id");

        CustomOAuth2User oAuth2User = new CustomOAuth2User(defaultOAuth2User, "github", "id");

        MockHttpServletResponse mockHttpServletResponse = new MockHttpServletResponse();

        userService.loginUser(oAuth2User, mockHttpServletResponse);

        CommonLoginResponse loginResponse = new ObjectMapper().readValue(mockHttpServletResponse.getContentAsString(), CommonLoginResponse.class);

        String oauthAccessToken = loginResponse.getAccessToken();
        String oauthRefreshToken = loginResponse.getRefreshToken();

        Long expectedOAuthUserId = userRepository.findByUsername(oAuth2User.getName())
                .orElseThrow()
                .getId();

        Assertions.assertThat(tokenProvider.decode(oauthAccessToken).getSubject()).isEqualTo(String.valueOf(expectedOAuthUserId));
        Assertions.assertThat(tokenProvider.decode(oauthRefreshToken).getSubject()).isEqualTo(String.valueOf(expectedOAuthUserId));
    }

    @Test
    void checkTokenAfterNameChange() throws AccessDeniedException {

        // 1. @BeforeEach에서 받은 Access·Refresh Token과 "test" 회원의 DB ID를 준비한다.
        User user = userRepository.findByUsername("test").get();
        Long expectedId = user.getId();

        InfoUpdateRequest infoUpdateRequest = InfoUpdateRequest.builder()
                .username("test")
                .newName("newTest")
                .build();

        // 2. 기존 Access Token으로 얻은 인증 상태에서 해당 회원의 사용자명을 변경한다.
        Authentication authentication = tokenProvider.getAuthentication(accessToken);

        try {
            SecurityContextHolder.getContext().setAuthentication(authentication);
            userService.changeUserInfo(infoUpdateRequest);

            // 3. 기존 Access Token으로 다시 인증하고 principal의 회원 ID를 저장해 둔 ID와 비교한다.
            Long principalId = ((CustomUserDetails) tokenProvider.getAuthentication(accessToken).getPrincipal()).getUser().getId();
            Assertions.assertThat(expectedId).isEqualTo(principalId);


            // 4. 기존 Refresh Token으로 새 Access Token을 받아 sub를 저장해 둔 ID와 비교한다.
            MockHttpServletRequest mockRequest = new MockHttpServletRequest();
            mockRequest.addHeader("Authorization", "Bearer " + refreshToken);
            String newAccessToken = tokenService.refreshAccessToken(mockRequest);
            Assertions.assertThat(tokenProvider.decode(newAccessToken).getSubject()).isEqualTo(String.valueOf(expectedId));
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    @Test
    void rejectsTokenForUnknownUserId() {
        // 1. 존재하지 않는 회원 ID를 가리키는 토큰으로 인증이 거부되는지 확인한다.
        Long invalidUserId = 999L;
        String invalidIdToken = tokenProvider.generateToken(invalidUserId, TokenType.ACCESS);
        Assertions.assertThatThrownBy(() -> tokenProvider.getAuthentication(invalidIdToken))
                .isInstanceOf(UsernameNotFoundException.class);

    }

    @Test
    void rejectsLegacyTokenWithUsernameSubject() {
        // 2. 기존 사용자명 형식 토큰은 회원 ID를 읽는 단계에서 거부되는지 별도 테스트로 확인한다.
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(15, ChronoUnit.MINUTES);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("jmna-auth-server")
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .subject("test")
                .claim("type", "access")
                .build();

        String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        Assertions.assertThatThrownBy(() -> tokenProvider.getUserId(token))
                .isInstanceOf(InvalidJWTException.class);
    }
    @Test
    void legacyTokenWithoutSubInfo() {
        // 2. 기존 사용자명 형식 토큰은 회원 ID를 읽는 단계에서 거부되는지 별도 테스트로 확인한다.
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(15, ChronoUnit.MINUTES);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("jmna-auth-server")
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .subject("123")
                .claim("type", "access")
                .build();

        String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        Jwt jwt = tokenProvider.decode(token);

        Assertions.assertThatThrownBy(() -> tokenProvider.getUserId(token))
                .isInstanceOf(InvalidJWTException.class);
    }

    @Test
    void findUserRefreshToken() {
        // 1. @BeforeEach에서 로그인한 "test" 회원을 DB에서 조회한다.
        User user = userRepository.findByUsername("test").get();
        // 2. user.getRefreshToken().getId()를 기대값으로 준비한다.
        Long expectedId = user.getRefreshToken().getId();
        // 3. tokenService.findUserRefreshToken(user.getId())를 호출한다.
        RefreshToken userRefreshToken = tokenService.findUserRefreshToken(user.getId());
        // 4. 반환된 Refresh Token의 ID를 기대값과 비교한다.
        Assertions.assertThat(expectedId).isEqualTo(userRefreshToken.getId());
    }

    @Test
    void verifyRefreshToken() {
        Assertions.assertThat(tokenService.verifyRefreshToken(refreshToken)).isTrue();
    }


    @Test
    void getTokenUsername() {
        Long userId = tokenService.getTokenUserId(mockHttpServletRequest);

        Long expectedId = userRepository.findByUsername("test").get().getId();

        Assertions.assertThat(expectedId).isEqualTo(userId);
    }

    @Test
    void deleteUserToken() {
        User user = userRepository.findByUsername("test").orElseThrow();
        tokenService.deleteUserToken(user);
        Assertions.assertThatThrownBy(() -> tokenRepository.findByTokenValue(refreshToken).orElseThrow())
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
