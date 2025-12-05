package com.jmna.auth.oauth;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "oauth")
public class OAuth2Properties {

    private Kakao kakao = new Kakao();
    private Naver naver = new Naver();
    private Github github = new Github();
    private Google google = new Google();

    @Getter @Setter
    public static class Kakao {
        private String clientId;
        private String clientSecret;
    }

    @Getter @Setter
    public static class Naver {
        private String clientId;
        private String clientSecret;
    }

    @Getter @Setter
    public static class Github {
        private String clientId;
        private String clientSecret;
    }

    @Getter @Setter
    public static class Google {
        private String clientId;
        private String clientSecret;
    }
}
