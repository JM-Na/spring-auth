package com.jmna.auth.exception;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // Body에 값이 적절하지 않거나 존재하지 않는 경우.
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<?> handleInvalidRequestBody(HttpMessageNotReadableException exception){
        return ResponseEntity
                .badRequest()
                .body("Invalid or missing request body");
    }

    @ExceptionHandler(InvalidJWTException.class)
    public ResponseEntity<?> handleInvalidRefreshToken() {
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body("JWT가 유효하지 않거나 존재하지 않습니다.");
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<?> handleWrongPassword() {
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body("잘못된 정보입니다. 다시 입력해주세요.");
    }

    @ExceptionHandler(InvalidUsernameException.class)
    public ResponseEntity<?> handleDuplicateUsername() {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body("동일한 사용자명이 이미 존재합니다.");
    }
}
