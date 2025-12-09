package com.jmna.auth.config;

import com.jmna.auth.filter.CustomJwtAuthenticationFilter;
import com.jmna.auth.filter.CustomLoginAuthenticationFilter;
import com.jmna.auth.handler.CustomLoginFailureHandler;
import com.jmna.auth.handler.CustomLoginSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final CustomJwtAuthenticationFilter jwtFilter;
    private final AuthenticationConfiguration authenticationConfiguration;

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public CustomLoginAuthenticationFilter customLoginAuthenticationFilter(AuthenticationManager authenticationManager,
                                                       CustomLoginSuccessHandler customLoginSuccessHandler,
                                                       CustomLoginFailureHandler customLoginFailureHandler){
        var customLoginAuthenticationFilter = new CustomLoginAuthenticationFilter(authenticationManager);
        customLoginAuthenticationFilter.setAuthenticationFailureHandler(customLoginFailureHandler);
        customLoginAuthenticationFilter.setAuthenticationSuccessHandler(customLoginSuccessHandler);
        return customLoginAuthenticationFilter;
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                          CustomLoginAuthenticationFilter loginFilter) throws Exception {

        http
                .authorizeHttpRequests(
                        auth -> auth
                                .requestMatchers(
                                        "/auth/**",
                                        "/error/**"
                                ).permitAll()
                                .anyRequest().authenticated()
                )
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
