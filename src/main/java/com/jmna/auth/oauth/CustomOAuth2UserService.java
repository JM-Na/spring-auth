package com.jmna.auth.oauth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.util.Map;


@Component
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final OidcUserService oidcUserService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        Object rawProviderId;
        String providerId;

        switch (registrationId) {
            case "github", "kakao" -> rawProviderId = oAuth2User.getAttribute("id");
            case "naver" -> {
                Object response = oAuth2User.getAttribute("response");
                rawProviderId = response instanceof Map<?, ?> profile
                        ? profile.get("id")
                        : null;
            }
            default -> throw new OAuth2AuthenticationException("유효하지 않은 공급자명입니다.");
        }

        boolean isValid = rawProviderId instanceof Number || (rawProviderId instanceof String id && !id.isBlank());

        if (!isValid) {
            throw new OAuth2AuthenticationException("사용자 ID가 정상적으로 반환되지 않았습니다.");
        }

        if (rawProviderId instanceof String) {
            providerId = (String) rawProviderId;
        } else {
            providerId = String.valueOf(rawProviderId);
        }

        String nameAttributeKey = userRequest.getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();

        // TODO(#8): 5-3. 공급자별 이메일과 검증 여부를 읽어 로그인 서비스로 전달한다.
        // GitHub는 /user/emails의 대표 주소 및 verified 값을, 카카오는 kakao_account의 이메일과 유효·인증 상태를 확인한다.
        // 네이버 response.email은 후보 주소로 전달하고, 이메일 확인이 필요한 상태는 5-4에서 처리한다.
        return new CustomOAuth2User(oAuth2User, registrationId, nameAttributeKey, providerId);
    }
}
