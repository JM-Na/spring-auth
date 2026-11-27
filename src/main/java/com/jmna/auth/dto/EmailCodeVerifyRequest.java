package com.jmna.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class EmailCodeVerifyRequest {
    @NotBlank(message = "유효하지 않은 요청입니다.")
    private String challengeId;
    // TODO(#8): 5-1.2. verifyCode가 숫자 6자리인지 검사하고 앞자리 0을 유지하도록 String으로 받는다.
    @NotBlank(message = "인증코드 형식이 올바르지 않습니다.")
    private String verifyCode;
}
