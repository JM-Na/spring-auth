package com.jmna.auth.oauth;

import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

/**
 * Google 같은 OIDC 로그인에서 Spring의 기본 사용자 로딩을 확장한다.
 * 성공 핸들러는 반환된 OidcUser의 ID 토큰에서 sub를 읽어 외부 계정 ID로 사용한다.
 */
@Service
public class CustomOidcUserService extends OidcUserService {

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);
        String subject = oidcUser.getIdToken().getSubject();

        if (subject == null || subject.trim().isEmpty()) {
            throw new OAuth2AuthenticationException("sub값이 유효하지 않거나 존재하지 않습니다.");
        }

        return oidcUser;
    }
}
