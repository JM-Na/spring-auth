package com.jmna.auth.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
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

}
