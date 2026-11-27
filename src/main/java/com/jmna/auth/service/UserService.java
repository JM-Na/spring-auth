package com.jmna.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jmna.auth.dto.*;
import com.jmna.auth.entity.RefreshToken;
import com.jmna.auth.entity.Roles;
import com.jmna.auth.entity.User;
import com.jmna.auth.exception.InvalidUsernameException;
import com.jmna.auth.jwt.JwtTokenProvider;
import com.jmna.auth.jwt.TokenType;
import com.jmna.auth.oauth.CustomOAuth2User;
import com.jmna.auth.repository.UserRepository;
import com.jmna.auth.userdetails.SecurityUtils;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.BadRequestException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.time.Duration;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final JwtTokenProvider tokenProvider;
    private final RedisTemplate<String, Object> redisTemplate;

    // TODO(#8): 5-1.2. EmailService에서 코드 비교를 구현한 뒤, 실패 시 기존 TTL을 유지하며 시도 횟수를 차감한다.
    // 코드가 맞으면 한 번만 사용 완료 처리하고 새 emailVerificationId를 발급한다.
    // signup:email:verified:<emailVerificationId>에 검증된 이메일과 검증 시점을 TTL(예시 10분)과 함께 저장한다.

    public void registerUser(SignupRequest dto) {
        // TODO(#8): 5-1.3. 회원 생성 전에 emailVerificationId로 signup:email:verified 키를 조회한다.
        // 키가 없거나 가입 요청의 정규화된 이메일이 Redis의 이메일과 다르면 가입을 중단한다.
        // 검증한 이메일과 검증 시점은 Redis에서 읽어 User에 저장한다. 이메일 유일 제약 위반은 중복 가입으로 처리한다.
        if (userRepository.findByUsername(dto.getUsername()).isPresent()) {
            log.error("회원가입 오류: 동일한 사용자명이 이미 존재합니다.");
            throw new IllegalArgumentException("동일한 사용자명이 이미 존재합니다.");
        }
        if (Objects.equals(dto.getUsername(), "") || Objects.equals(dto.getPassword(), "")) {
            log.error("회원가입 오류: 사용자명 또는 비밀번호가 입력되지 않았습니다.");
            throw new IllegalArgumentException("사용자명 또는 비밀번호가 입력되지 않았습니다.");
        }
        User user = User.builder()
                .username(dto.getUsername())
                .password(passwordEncoder.encode(dto.getPassword()))
                .registrationId("local")
                .roles(List.of(Roles.ROLE_USER))
                .build();
        userRepository.save(user);
        // 회원 저장이 확정된 뒤 가입 확인값을 Redis에서 삭제해 재사용을 막는다.
        log.info("회원가입 성공, 사용자명: {}", dto.getUsername());
    }

    @PreAuthorize("#dto.username == principal.user.username")
    public void deleteUser(PasswordCheckRequest dto) throws AccessDeniedException {
        User user = SecurityUtils.getCurrentUser();
        if (passwordEncoder.matches(dto.getPassword(), user.getPassword())) {
            userRepository.delete(user);
            log.info("회원탈퇴 성공, 사용자명: {}", user.getUsername());
        } else {
            log.error("회원탈퇴 오류: 비밀번호 확인에 실패했습니다.");
            throw new BadCredentialsException("잘못된 정보입니다. 다시 입력해주세요.");
        }
    }

    @PreAuthorize("#dto.username == principal.user.username")
    public void changePassword(PasswordChangeRequest dto) throws AccessDeniedException {
        User user = SecurityUtils.getCurrentUser();
        if (passwordEncoder.matches(dto.getCurrentPassword(), user.getPassword())) {
            user.updatePassword(passwordEncoder.encode(dto.getNewPassword()));
            userRepository.save(user);
            log.info("비밀번호 변경 성공, 사용자명: {}", user.getUsername());
        } else {
            log.error("비밀번호 변경 오류: 비밀번호 확인에 실패했습니다.");
            throw new BadCredentialsException("잘못된 정보입니다. 다시 입력해주세요.");
        }
    }

    @PreAuthorize("#dto.username == principal.user.username")
    public void changeUserInfo(InfoUpdateRequest dto) throws AccessDeniedException {
        if (dto.getNewName() == null || dto.getNewName().trim().isEmpty()) {
            log.error("사용자 정보 변경 오류: 새 사용자명이 유효하지 않습니다.");
            throw new InvalidUsernameException();
        }

        User user = SecurityUtils.getCurrentUser();
        if (userRepository.findByUsername(dto.getNewName()).isPresent()) {
            log.error("사용자 정보 변경 오류: 동일한 사용자명이 이미 존재합니다.");
            throw new InvalidUsernameException();
        }
        user.updateDetails(dto);
        userRepository.save(user);
        log.info("사용자 정보 변경 성공: {}", user.getUsername());
    }

    @PreAuthorize("#dto.username == principal.user.username")
    public Boolean checkPassword(PasswordCheckRequest dto) throws AccessDeniedException {
        User user = SecurityUtils.getCurrentUser();
        return passwordEncoder.matches(dto.getPassword(), user.getPassword());
    }

    // 일반 유저 로그인 처리
    public void loginUser(Long userId, HttpServletResponse response) throws IOException {
        // JWT 생성
        String accessToken = tokenProvider.generateToken(userId, TokenType.ACCESS);
        String refreshToken = tokenProvider.generateToken(userId, TokenType.REFRESH);

        User user = userRepository.findById(userId).orElseThrow();

        saveUserAndToken(refreshToken, user);

        setLoginResponse(response, "로그인에 성공했습니다.", accessToken, refreshToken, "local");
    }

    // TODO(#8): 5-4. 먼저 SocialAccount에서 registrationId와 providerId로 조회한다.
    // 연결된 회원이 있으면 내부 회원 ID로 토큰을 발급한다.
    public SocialLoginResult loginUser(CustomOAuth2User oAuth2User, HttpServletResponse response) throws IOException {

        String registrationId = oAuth2User.getRegistrationId();
        String providerId = oAuth2User.getProviderId();

        Optional<User> userOptional = userRepository.findByRegistrationIdAndProviderId(registrationId, providerId);

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            Long userId = user.getId();

            // 신규 가입이나 연동을 완료한 경우에도 확정된 내부 회원 ID로 이 발급·저장 순서를 재사용한다.
            String accessToken = tokenProvider.generateToken(userId, TokenType.ACCESS);
            String refreshToken = tokenProvider.generateToken(userId, TokenType.REFRESH);

            saveUserAndToken(refreshToken, user);

            CommonLoginResponse body = CommonLoginResponse.builder()
                    .message("소셜 로그인에 성공했습니다.")
                    .registrationId(registrationId)
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .build();

            return SocialLoginResult.success(body);
        }

        // TODO(#8): 5-4. 연결된 회원이 없으면 검증이 확인된 이메일로 기존 회원을 조회한다.
        // 이메일을 확인할 수 없으면 EMAIL_VERIFICATION_REQUIRED로 보내고, 확인 후 다시 조회한다.
        // 일치 회원이 있으면 LINK_REQUIRED로 보내고, 확인한 이메일로 조회한 결과가 없을 때 신규 회원을 생성한다.
        // 대기 요청에는 검증한 소셜 계정 조합, 진행 단계, 있으면 기존 회원 ID를 담아 만료 시간을 설정한다.
        // 후속 요청에서 같은 브라우저의 대기 상태를 확인하고, 확인·연동이 끝나기 전에는 토큰을 발급하지 않는다.
        String requestId = UUID.randomUUID().toString();
        String redisKey = "social-login:pending:" + requestId;
        Map<String, String> value = new HashMap<>();
        value.put("registrationId", registrationId);
        value.put("providerId", providerId);
        redisTemplate.opsForValue().set(redisKey, value, Duration.ofMinutes(5));

        return SocialLoginResult.signUpOrLinkRequired(requestId);
    }

    // TODO(#8): 5-5. 이메일까지 조회한 결과가 없을 때 호출하는 신규 회원 저장 메서드로 바꾼다.
    // 검증된 이메일과 소셜 계정 조합을 받고, 기본 사용자명과 ROLE_USER를 지정한다.
    public void signUpOAuth2User(String requestId) throws BadRequestException {
        // User와 SocialAccount를 같은 트랜잭션에 저장하고, 내부 ID가 채워진 User를 공통 토큰 발급으로 넘긴다.
        // 유일 제약 충돌은 롤백 이후에 처리한다. 사용자명 충돌은 이름을 새로 만들고, 이메일이나 소셜 계정 충돌은 재조회한다.
        String redisKey = "social-login:pending:" + requestId;
        Object stored = redisTemplate.opsForValue().get(redisKey);

        if (!(stored instanceof Map<?, ?> pending)
                || !(pending.get("registrationId") instanceof String registrationId) || registrationId.trim().isEmpty()
                || !(pending.get("providerId") instanceof String providerId) || providerId.trim().isEmpty()) {
            throw new BadRequestException();
        }



    }

    // TODO(#8): 5-5. 이메일 조회로 찾은 회원을 기존 로그인이나 서비스의 복구 절차로 인증한 뒤 소셜 계정을 연결한다.
    public void linkUpOAuth2User() {
        // 인증된 내부 회원 ID가 대기 요청에 보관한 회원 ID와 같은지 확인한다.
        // 다른 회원에 연결된 소셜 계정이면 충돌로 처리한다. 연결이 확정되면 대기 요청을 소모하고 토큰을 발급한다.
    }

    @PreAuthorize("#dto.username == principal.user.username")
    public void logoutUser(LogoutRequest dto) throws AccessDeniedException {
        User user = SecurityUtils.getCurrentUser();
        tokenService.deleteUserToken(user);
        log.info("로그아웃 성공: {}", user.getUsername());
    }

    // 응답 JSON 생성
    private void setLoginResponse(HttpServletResponse response, String message,
                                  String accessToken, String refreshToken, String registrationId) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json;charset=UTF-8");

        CommonLoginResponse loginResponse = CommonLoginResponse.builder()
                .message(message)
                .registrationId(registrationId)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();

        response.getWriter().write(objectMapper.writeValueAsString(loginResponse));
    }

    //  RefreshToken 저장 (DB/Redis)
    // 토큰, 유저 생성 및 저장
    private void saveUserAndToken(String refreshToken, User user) {
        userRepository.save(user);
        RefreshToken token = new RefreshToken(refreshToken, user);
        user.setToken(token);
        tokenService.saveRefreshToken(token);
        userRepository.save(user);
    }
}
