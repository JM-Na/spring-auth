package com.jmna.auth.oauth;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;

@Getter
public class CustomOAuth2User extends DefaultOAuth2User {

    private String username;
    private String registrationId;
    private String providerId;
    // TODO(#8): 5-3. 공급자에서 읽은 이메일과 검증 여부를 일반 OAuth2와 OIDC에서 같은 형태로 넘긴다.

    public CustomOAuth2User(OAuth2User oAuth2User, String registrationId, String nameAttributeKey, String providerId) {
        super(oAuth2User.getAuthorities(), oAuth2User.getAttributes(), nameAttributeKey);
        this.username = oAuth2User.getName();
        // 이메일을 다루기 전에 공급자 속성 전체를 출력하는 이 로그를 정리한다.
        System.out.println("oAuth2User = " + oAuth2User);
        this.registrationId = registrationId;
        this.providerId = providerId;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return super.getAttributes();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return super.getAuthorities();
    }

    @Override
    public String getName() {
        return super.getName();
    }
}
