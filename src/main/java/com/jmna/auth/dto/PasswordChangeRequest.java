package com.jmna.auth.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class PasswordChangeRequest {
    private String currentPassword;
    private String newPassword; // 새 비밀번호와 새 비밀번호 확인을 비교하는 역할은 프론트엔드에서
}
