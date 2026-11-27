package com.jmna.auth.config;

import com.jmna.auth.handler.CustomOAuth2LoginSuccessHandler;
import com.jmna.auth.oauth.CustomOAuth2Provider;
import com.jmna.auth.oauth.CustomOAuth2UserService;
import com.jmna.auth.oauth.CustomOidcUserService;
import com.jmna.auth.oauth.OAuth2Properties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
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
                                                  CustomOidcUserService customOidcUserService,
                                                  CustomOAuth2LoginSuccessHandler oAuth2LoginSuccessHandler) throws Exception {
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
                        .userInfoEndpoint(info -> info
                                .userService(customOAuth2UserService)
                                .oidcUserService(customOidcUserService)
                        )
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

        // TODO(#8): 5-3. GitHub의 요청 스코프에 이메일 조회에 필요한 user:email을 포함한다.
        ClientRegistration github = CommonOAuth2Provider.GITHUB
                .getBuilder("github")
                .clientId(oAuth2Properties.getGithub().getClientId())
                .clientSecret(oAuth2Properties.getGithub().getClientSecret())
                .build();

        // TODO(#8): 5-3. Google의 요청에 openid와 email 스코프가 포함되는지 확인한다.
        ClientRegistration google = CommonOAuth2Provider.GOOGLE
                .getBuilder("google")
                .clientId(oAuth2Properties.getGoogle().getClientId())
                .clientSecret(oAuth2Properties.getGoogle().getClientSecret())
                .build();

        return new InMemoryClientRegistrationRepository(kakao, naver, github, google);
    }
}
