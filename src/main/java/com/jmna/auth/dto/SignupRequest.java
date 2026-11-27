package com.jmna.auth.dto;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class SignupRequest {
    private String username;
    private String password;
    // TODO(#8): 5-1.3. 최종 가입 요청에 email과 코드 확인 API가 반환한 emailVerificationId를 받는다.
    // 가입 서비스가 Redis에 보관한 확인 결과와 요청 이메일을 대조한다.
}
