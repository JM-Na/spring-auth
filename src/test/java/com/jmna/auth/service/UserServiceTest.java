package com.jmna.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jmna.auth.dto.*;
import com.jmna.auth.entity.User;
import com.jmna.auth.exception.InvalidUsernameException;
import com.jmna.auth.repository.UserRepository;
import com.jmna.auth.userdetails.CustomUserDetails;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.AccessDeniedException;
import java.util.NoSuchElementException;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@Transactional
@AutoConfigureMockMvc
@ActiveProfiles("test")
@SpringBootTest
class UserServiceTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    UserService userService;
    @Autowired
    UserRepository userRepository;
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

    @Nested
    class ChangeUserInfoTests {
        @Test
        void 회원정보_변경_인증시() throws AccessDeniedException {
            registerAndAuthenticateMember("test", "test");

            User user = userRepository.findByUsername("test").get();

            InfoUpdateRequest dto = InfoUpdateRequest.builder()
                    .username("test")
                    .newName("newTest")
                    .build();

            userService.changeUserInfo(dto);

            Assertions
                    .assertThatThrownBy(() -> userRepository.findByUsername("test").orElseThrow())
                    .isInstanceOf(NoSuchElementException.class);

            Assertions.assertThat(userRepository.findByUsername("newTest").isPresent());

            Assertions.assertThat(userRepository.findById(user.getId()).get().getUsername()).isEqualTo("newTest");
        }

        @Test
        void 회원정보_변경_미인증시() {
            SignupRequest dto = SignupRequest.builder()
                    .username("test")
                    .password("test")
                    .build();

            userService.registerUser(dto);

            User user = userRepository.findByUsername("test").get();

            SecurityContextHolder.clearContext();

            InfoUpdateRequest infoUpdateRequest = InfoUpdateRequest.builder()
                    .username("test")
                    .newName("newTest")
                    .build();

            // 인증이 존재하지 않으면 AuthenticationCredentialsNotFouncException을 반환함.
            Assertions
                    .assertThatThrownBy(() -> userService.changeUserInfo(infoUpdateRequest))
                    .hasRootCauseInstanceOf(AuthenticationCredentialsNotFoundException.class);

            // 위의 메서드 실행이 실패하여서 사용자의 이름이 변경되지 않음.
            Assertions
                    .assertThat(userRepository.findById(user.getId()).get().getUsername())
                    .isEqualTo("test");
        }

        @Test
        void 회원정보_변경_중복() {
            // 변경할 사용자 생성
            registerAndAuthenticateMember("user1", "test");

            User user1 = userRepository.findByUsername("user1").get();

            // 중복 닉네임 대상이 될 사용자 생성
            SignupRequest dto = SignupRequest.builder()
                    .username("user2")
                    .password("test")
                    .build();

            userService.registerUser(dto);

            User user2 = userRepository.findByUsername("user2").get();

            InfoUpdateRequest request = InfoUpdateRequest.builder()
                    .username("user1")
                    .newName("user2")
                    .build();

            Assertions
                    .assertThatThrownBy(() -> userService.changeUserInfo(request))
                    .isInstanceOf(InvalidUsernameException.class);

            Assertions
                    .assertThat(userRepository.findById(user1.getId()).get().getUsername())
                    .isEqualTo("user1");

            Assertions
                    .assertThat(userRepository.findById(user2.getId()).get().getUsername())
                    .isEqualTo("user2");
        }
    }

    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    @Nested
    class AfterLoginTests {
        @BeforeEach
        void 회원가입_후_로그인() {
            registerAndAuthenticateMember("test", "test");
        }

        @Test
        void 비밀번호_변경() throws AccessDeniedException {
            PasswordChangeRequest dto = PasswordChangeRequest.builder()
                    .username("test")
                    .currentPassword("test")
                    .newPassword("test1")
                    .build();

            userService.changePassword(dto);
            User user = userRepository.findByUsername("test").orElseThrow();
            String password = user.getPassword();
            Assertions.assertThat(passwordEncoder.matches("test1", password)).isTrue();
        }

        @Test
        void 비밀번호_확인() throws AccessDeniedException {
            PasswordCheckRequest dto = PasswordCheckRequest.builder()
                    .username("test")
                    .password("test1")
                    .build();

            Assertions.assertThat(userService.checkPassword(dto)).isFalse();
        }

        @Test
        void 회원_탈퇴() throws AccessDeniedException {
            PasswordCheckRequest dto = PasswordCheckRequest.builder()
                    .username("test")
                    .password("test")
                    .build();

            userService.deleteUser(dto);

            Assertions.assertThatThrownBy(() -> userRepository.findByUsername("test").orElseThrow())
                    .isInstanceOf(NoSuchElementException.class);
        }
    }

    private void registerAndAuthenticateMember(String username, String password) {
        SignupRequest dto = SignupRequest.builder()
                .username(username)
                .password(password)
                .build();

        userService.registerUser(dto);

        CustomUserDetails principal = new CustomUserDetails(userRepository.findByUsername(username).orElseThrow());
        Authentication authentication =
                new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
