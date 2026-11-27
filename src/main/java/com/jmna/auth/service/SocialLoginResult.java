package com.jmna.auth.service;

import com.jmna.auth.dto.CommonLoginResponse;

public record SocialLoginResult (Status status, CommonLoginResponse loginResponse, String requestId){
    // TODO(#8): 5-4. 이메일 확인 필요와 기존 계정 연결 필요를 서로 다른 상태로 나타낸다.
    // 로그인 성공에는 토큰 응답을, 대기 상태에는 requestId를 담는다.
    public enum Status {
        LOGIN_SUCCESS,
        SIGNUP_OR_LINK_REQUIRED
    }

    public static SocialLoginResult success(CommonLoginResponse loginResponse) {
        return new SocialLoginResult(Status.LOGIN_SUCCESS, loginResponse, null);
    }

    public static SocialLoginResult signUpOrLinkRequired(String requestId) {
        return new SocialLoginResult(Status.SIGNUP_OR_LINK_REQUIRED, null, requestId);
    }
}
