package com.jmna.auth.handler;

import com.jmna.auth.oauth.CustomOAuth2User;
import com.jmna.auth.service.SocialLoginResult;
import com.jmna.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomOAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final UserService userService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        if (authentication instanceof OAuth2AuthenticationToken oAuth2Token) {
            String registrationId = oAuth2Token.getAuthorizedClientRegistrationId();

            String providerId;
            CustomOAuth2User customOAuth2User;
            OAuth2User oAuth2User = oAuth2Token.getPrincipal();
            if (oAuth2User instanceof OidcUser oidcUser) {
                // TODO(#8): 5-3. 검증된 Google ID 토큰에서 email과 email_verified를 읽어 함께 전달한다.
                // 공급자가 소유를 확인해 줄 수 없는 주소는 서비스 이메일 인증이 필요한 상태로 넘긴다.
                providerId = oidcUser.getIdToken().getSubject();
                customOAuth2User = new CustomOAuth2User(oidcUser, registrationId, "sub", providerId);
            } else if (oAuth2User instanceof CustomOAuth2User existingUser) {
                customOAuth2User = existingUser;
            } else {
                throw new OAuth2AuthenticationException("invalid_principal");
            }

            // TODO(#8): 5-4. loginUser()를 한 번 호출하고 서비스가 결정한 결과에 따라 응답한다.
            SocialLoginResult socialLoginResult = userService.loginUser(customOAuth2User, response);

            if (socialLoginResult.status().equals(SocialLoginResult.Status.LOGIN_SUCCESS)) {
                // 서비스가 반환한 토큰 데이터를 여기서 HTTP 응답으로 작성한다.
            } else if (socialLoginResult.status().equals(SocialLoginResult.Status.SIGNUP_OR_LINK_REQUIRED)) {
                // 이메일 인증 필요와 기존 계정 연결 필요를 각각 상태와 requestId로 응답한다.
                // 아래 가입 호출은 5-5 서비스 흐름으로 옮기고, 대기 응답을 여기서 마친다.
                userService.signUpOAuth2User(socialLoginResult.requestId());
            }


        } else {
            throw new OAuth2AuthenticationException("invalid_authentication_type");
        }



    }
}
