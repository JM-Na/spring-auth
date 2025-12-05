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
    private String provider;

    public CustomOAuth2User(OAuth2User oAuth2User, String provider, String nameAttributeKey) {
        super(oAuth2User.getAuthorities(), oAuth2User.getAttributes(), nameAttributeKey);
        this.username = oAuth2User.getName();
        System.out.println("oAuth2User = " + oAuth2User);
        this.provider = provider;
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
