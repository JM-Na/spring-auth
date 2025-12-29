package com.jmna.auth.userdetails;

import com.jmna.auth.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.nio.file.AccessDeniedException;

@Slf4j
@Component
public class SecurityUtils {

    public static User getCurrentUser() throws AccessDeniedException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            log.error("SecurityContext 오류: 인증되지 않은 사용자입니다.");
            throw new AccessDeniedException("인증되지 않은 사용자입니다.");
        }

        return ((CustomUserDetails) authentication.getPrincipal()).getUser();
    }

}
