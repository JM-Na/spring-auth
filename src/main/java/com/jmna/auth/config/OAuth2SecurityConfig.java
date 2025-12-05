package com.jmna.auth.config;

import com.jmna.auth.handler.CustomOAuth2LoginSuccessHandler;
import com.jmna.auth.oauth.CustomOAuth2Provider;
import com.jmna.auth.oauth.CustomOAuth2UserService;
import com.jmna.auth.oauth.OAuth2Properties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class OAuth2SecurityConfig {

    private final OAuth2Properties oAuth2Properties;

    @Bean
    @Order(1)
    SecurityFilterChain oAuth2SecurityFilterChain(HttpSecurity http,
                                                  CustomOAuth2UserService customOAuth2UserService,
                                                  CustomOAuth2LoginSuccessHandler oAuth2LoginSuccessHandler) throws Exception {
        var authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        http
                .securityMatcher("/oauth2/**", "/login/oauth2/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/oauth2/**",
                                "/login/oauth2/**"
                        ).permitAll()
                        .anyRequest().denyAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .clientRegistrationRepository(clientRegistrationRepository())
                        .userInfoEndpoint(info -> info.userService(customOAuth2UserService))
                        .successHandler(oAuth2LoginSuccessHandler)
                )
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {

        ClientRegistration kakao = CustomOAuth2Provider.KAKAO
                .getBuilder("kakao")
                .clientId(oAuth2Properties.getKakao().getClientId())
                .clientSecret(oAuth2Properties.getKakao().getClientSecret())
                .build();

        ClientRegistration naver = CustomOAuth2Provider.NAVER
                .getBuilder("naver")
                .clientId(oAuth2Properties.getNaver().getClientId())
                .clientSecret(oAuth2Properties.getNaver().getClientSecret())
                .build();

        ClientRegistration github = CommonOAuth2Provider.GITHUB
                .getBuilder("github")
                .clientId(oAuth2Properties.getGithub().getClientId())
                .clientSecret(oAuth2Properties.getGithub().getClientSecret())
                .build();

        ClientRegistration google = CommonOAuth2Provider.GOOGLE
                .getBuilder("google")
                .clientId(oAuth2Properties.getGoogle().getClientId())
                .clientSecret(oAuth2Properties.getGoogle().getClientSecret())
                .build();

        return new InMemoryClientRegistrationRepository(kakao, naver, github, google);
    }
}
